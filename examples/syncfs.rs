//! Filesystem for observing `syncfs(2)` behaviour.
//!
//! It serves writable files whose contents are discarded, and delays every
//! write reply, so a run shows how far writeback had got when `syncfs(2)`
//! returned. On a connection the kernel has not enabled `FUSE_SYNCFS` for,
//! `syncfs(2)` returns while writes are still in flight and no `SYNCFS` is
//! logged at all:
//!
//! ```text
//! # cargo run --example syncfs -- /tmp/mnt --write-delay-ms 500 &
//! # dd if=/dev/zero of=/tmp/mnt/f bs=1M count=8 && sync -f /tmp/mnt
//! ```
//!
//! The kernel enables it for virtiofs and, since Linux 6.18, for the `fuseblk`
//! filesystem type. Anything else needs the connection flag set out of band,
//! which `--enable-syncfs` does through the `fuse-syncfs` kernel module: it
//! hands this session's `/dev/fuse` descriptor to the module, which sets
//! `fuse_conn::sync_fs` on the connection behind it.

mod common;

use std::collections::HashMap;
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use clap::Parser;
use fuser::BsdFileFlags;
use fuser::Errno;
use fuser::FileAttr;
use fuser::FileHandle;
use fuser::FileType;
use fuser::Filesystem;
use fuser::FopenFlags;
use fuser::Generation;
use fuser::INodeNo;
use fuser::InitFlags;
use fuser::KernelConfig;
use fuser::LockOwner;
use fuser::MountOption;
use fuser::OpenFlags;
use fuser::ReplyAttr;
use fuser::ReplyCreate;
use fuser::ReplyData;
use fuser::ReplyDirectory;
use fuser::ReplyEmpty;
use fuser::ReplyEntry;
use fuser::ReplyWrite;
use fuser::Request;
use fuser::Session;
use fuser::TimeOrNow;
use fuser::WriteFlags;

use crate::common::args::CommonArgs;

#[derive(Parser)]
struct Args {
    #[clap(flatten)]
    common_args: CommonArgs,

    /// Delay every write reply by this many milliseconds.
    #[clap(long, default_value_t = 200)]
    write_delay_ms: u64,

    /// Ask the fuse-syncfs kernel module to enable FUSE_SYNCFS on this mount's
    /// connection, so that syncfs(2) waits for in-flight writes.
    #[cfg(target_os = "linux")]
    #[clap(long)]
    enable_syncfs: bool,
}

/// `FUSE_SYNCFS_IOC_ENABLE` of the out-of-tree `fuse-syncfs` module, which takes
/// the `/dev/fuse` descriptor of the connection to enable as its argument.
#[cfg(target_os = "linux")]
mod fuse_syncfs {
    pub const CONTROL_PATH: &str = "/proc/fuse_syncfs";
    nix::ioctl_write_int_bad!(enable, nix::request_code_none!(0xE5, 1));
}

const TTL: Duration = Duration::from_secs(1);

struct SyncFsFS {
    mounted_at: Instant,
    write_delay: Duration,
    /// File name and size per inode. Contents are discarded.
    files: RwLock<HashMap<u64, (String, u64)>>,
    next_ino: AtomicU64,
    writes_completed: AtomicU64,
    log_lock: Mutex<()>,
}

impl SyncFsFS {
    fn new(write_delay: Duration) -> Self {
        SyncFsFS {
            mounted_at: Instant::now(),
            write_delay,
            files: RwLock::new(HashMap::new()),
            next_ino: AtomicU64::new(2),
            writes_completed: AtomicU64::new(0),
            log_lock: Mutex::new(()),
        }
    }

    fn log(&self, message: &str) {
        let _guard = self.log_lock.lock().expect("log lock poisoned");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the unix epoch");
        println!(
            "[{:.3}] {:>8.3}s {message}",
            now.as_secs_f64(),
            self.mounted_at.elapsed().as_secs_f64()
        );
    }

    fn attr(&self, ino: INodeNo, size: u64, kind: FileType) -> FileAttr {
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm: if kind == FileType::Directory {
                0o755
            } else {
                0o644
            },
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    fn file_attr(&self, ino: INodeNo) -> Option<FileAttr> {
        if ino == INodeNo::ROOT {
            return Some(self.attr(ino, 0, FileType::Directory));
        }
        let files = self.files.read().expect("files lock poisoned");
        let (_, size) = files.get(&ino.0)?;
        Some(self.attr(ino, *size, FileType::RegularFile))
    }
}

impl Filesystem for SyncFsFS {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // Without the writeback cache the kernel writes through synchronously,
        // leaving nothing for syncfs to wait for.
        config
            .add_capabilities(InitFlags::FUSE_WRITEBACK_CACHE)
            .map_err(|missing| {
                io::Error::other(format!("kernel lacks writeback cache support: {missing:?}"))
            })?;
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        let files = self.files.read().expect("files lock poisoned");
        match files
            .iter()
            .find(|(_, (file_name, _))| OsStr::new(file_name) == name)
        {
            Some((ino, (_, size))) => reply.entry(
                &TTL,
                &self.attr(INodeNo(*ino), *size, FileType::RegularFile),
                Generation(0),
            ),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.file_attr(ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if let Some(size) = size {
            let mut files = self.files.write().expect("files lock poisoned");
            if let Some((_, file_size)) = files.get_mut(&ino.0) {
                *file_size = size;
            }
        }
        match self.file_attr(ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if parent != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        let ino = INodeNo(self.next_ino.fetch_add(1, Ordering::SeqCst));
        self.files
            .write()
            .expect("files lock poisoned")
            .insert(ino.0, (name.to_owned(), 0));
        reply.created(
            &TTL,
            &self.attr(ino, 0, FileType::RegularFile),
            Generation(0),
            FileHandle(0),
            FopenFlags::empty(),
        );
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if parent != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        let mut files = self.files.write().expect("files lock poisoned");
        let ino = files
            .iter()
            .find(|(_, (file_name, _))| OsStr::new(file_name) == name)
            .map(|(ino, _)| *ino);
        match ino {
            Some(ino) => {
                files.remove(&ino);
                reply.ok();
            }
            None => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if self.file_attr(ino).is_none() {
            reply.error(Errno::ENOENT);
            return;
        }
        reply.data(&vec![0u8; size as usize]);
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let len = data.len();
        std::thread::sleep(self.write_delay);
        {
            let mut files = self.files.write().expect("files lock poisoned");
            let Some((_, size)) = files.get_mut(&ino.0) else {
                reply.error(Errno::ENOENT);
                return;
            };
            *size = (*size).max(offset + len as u64);
        }
        let completed = self.writes_completed.fetch_add(1, Ordering::SeqCst) + 1;
        self.log(&format!(
            "WRITE ino {} offset {offset} len {len} ({completed} writes completed)",
            ino.0
        ));
        reply.written(len as u32);
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.log(&format!("FSYNC ino {}", ino.0));
        reply.ok();
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn syncfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyEmpty) {
        self.log(&format!(
            "SYNCFS ({} writes completed)",
            self.writes_completed.load(Ordering::SeqCst)
        ));
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        let files = self.files.read().expect("files lock poisoned");
        let entries = [
            (INodeNo::ROOT, FileType::Directory, ".".to_owned()),
            (INodeNo::ROOT, FileType::Directory, "..".to_owned()),
        ]
        .into_iter()
        .chain(
            files
                .iter()
                .map(|(ino, (name, _))| (INodeNo(*ino), FileType::RegularFile, name.clone())),
        );
        for (i, (ino, kind, name)) in entries.enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as u64, kind, &name) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() {
    let args = Args::parse();
    env_logger::init();

    let mut cfg = args.common_args.config();
    cfg.mount_options
        .push(MountOption::FSName("syncfs".to_owned()));

    let fs = SyncFsFS::new(Duration::from_millis(args.write_delay_ms));
    let session = Session::new(fs, &args.common_args.mount_point, &cfg).unwrap();

    // The connection exists as soon as the mount does, and the flag shares an
    // unsynchronized word with the rest of the connection flags, so it has to be
    // set before the session serves anything.
    #[cfg(target_os = "linux")]
    if args.enable_syncfs {
        let control = File::open(fuse_syncfs::CONTROL_PATH).unwrap_or_else(|err| {
            panic!(
                "{} is unavailable ({err}): load the fuse-syncfs module",
                fuse_syncfs::CONTROL_PATH
            )
        });
        // Safety: the ioctl takes an int, and the session outlives the call.
        unsafe { fuse_syncfs::enable(control.as_raw_fd(), session.as_fd().as_raw_fd()) }
            .expect("the module refused to enable FUSE_SYNCFS on this connection");
    }

    session.run().unwrap();
}
