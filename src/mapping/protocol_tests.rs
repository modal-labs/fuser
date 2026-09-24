use std::ffi::OsStr;
use std::io;
use std::io::IoSlice;
use std::mem::{offset_of, size_of};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::time::{Duration, SystemTime};

use zerocopy::IntoBytes;

use crate::ll::fuse_abi as abi;
use crate::{
    BackingId, BsdFileFlags, CustomReplySender, DispatchContext, FileAttr, FileHandle, FileType,
    Filesystem, FilesystemMapping, FopenFlags, Generation, HandshakeOutcome, INodeNo, IdMap,
    KernelConfig, ReplyAttr, ReplyCreate, ReplyDirectoryPlus, ReplyEntry, ReplySender, Request,
    RequestWithSender, SessionACL, TimeOrNow, Uid,
};

const MAPPING: FilesystemMapping = FilesystemMapping {
    uid: IdMap::new(1, 100_000, 10_000),
    gid: IdMap::new(1, 200_000, 10_000),
};
const TTL: Duration = Duration::from_secs(3);

struct Sender(mpsc::Sender<Vec<u8>>);

impl CustomReplySender for Sender {
    fn send(&self, data: &[IoSlice<'_>]) -> io::Result<()> {
        self.0
            .send(data.iter().flat_map(|s| s.iter().copied()).collect())
            .unwrap();
        Ok(())
    }
}

fn sender() -> (ReplySender, mpsc::Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();
    (ReplySender::custom(Arc::new(Sender(tx))), rx)
}

fn packet(opcode: u32, body: &[u8]) -> Vec<u64> {
    let len = size_of::<abi::fuse_in_header>() + body.len();
    let mut packet = vec![0u64; len.div_ceil(8)];
    let bytes = packet.as_mut_slice().as_mut_bytes();
    let offset = offset_of!(abi::fuse_in_header, len);
    bytes[offset..offset + 4].copy_from_slice(&(len as u32).to_ne_bytes());
    let offset = offset_of!(abi::fuse_in_header, opcode);
    bytes[offset..offset + 4].copy_from_slice(&opcode.to_ne_bytes());
    let offset = offset_of!(abi::fuse_in_header, unique);
    bytes[offset..offset + 8].copy_from_slice(&123u64.to_ne_bytes());
    let offset = offset_of!(abi::fuse_in_header, nodeid);
    bytes[offset..offset + 8].copy_from_slice(&1u64.to_ne_bytes());
    let offset = offset_of!(abi::fuse_in_header, uid);
    bytes[offset..offset + 4].copy_from_slice(&7u32.to_ne_bytes());
    let offset = offset_of!(abi::fuse_in_header, gid);
    bytes[offset..offset + 4].copy_from_slice(&19u32.to_ne_bytes());
    let offset = offset_of!(abi::fuse_in_header, pid);
    bytes[offset..offset + 4].copy_from_slice(&42u32.to_ne_bytes());
    bytes[size_of::<abi::fuse_in_header>()..len].copy_from_slice(body);
    packet
}

fn attr() -> FileAttr {
    FileAttr {
        ino: INodeNo(2),
        size: 123,
        blocks: 1,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o644,
        nlink: 1,
        uid: 100_006,
        gid: 200_018,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

struct Probe {
    mapping: FilesystemMapping,
    deferred: Mutex<Option<ReplyAttr>>,
    ownership: Mutex<Option<(Option<u32>, Option<u32>)>>,
}

impl Probe {
    fn new(mapping: FilesystemMapping) -> Self {
        Self {
            mapping,
            deferred: Mutex::new(None),
            ownership: Mutex::new(None),
        }
    }

    fn check_credentials(&self, req: &Request) {
        assert_eq!(req.uid(), self.mapping.uid.to_filesystem(7));
        assert_eq!(req.gid(), self.mapping.gid.to_filesystem(19));
        assert_eq!(req.pid(), 42);
        assert_eq!(req.unique().0, 123);
    }
}

impl Filesystem for Probe {
    fn init(&mut self, req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
        self.check_credentials(req);
        Ok(())
    }

    fn lookup(&self, req: &Request, _parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        self.check_credentials(req);
        if name == "ttls" {
            reply.entry_with_ttls(&TTL, &TTL, &attr(), Generation(1));
        } else {
            reply.entry(&TTL, &attr(), Generation(1));
        }
    }

    fn getattr(&self, req: &Request, _ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        self.check_credentials(req);
        *self.deferred.lock().unwrap() = Some(reply);
    }

    fn setattr(
        &self,
        req: &Request,
        _ino: INodeNo,
        _mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        _size: Option<u64>,
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
        self.check_credentials(req);
        *self.ownership.lock().unwrap() = Some((uid, gid));
        reply.attr(&TTL, &attr());
    }

    fn create(
        &self,
        req: &Request,
        _parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        self.check_credentials(req);
        if name == "passthrough" {
            let backing = BackingId {
                channel: Weak::new(),
                backing_id: 123,
            };
            reply.created_passthrough(
                &TTL,
                &attr(),
                Generation(1),
                FileHandle(4),
                FopenFlags::empty(),
                &backing,
            );
        } else {
            reply.created(
                &TTL,
                &attr(),
                Generation(1),
                FileHandle(4),
                FopenFlags::empty(),
            );
        }
    }

    fn readdirplus(
        &self,
        req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        self.check_credentials(req);
        for (offset, name) in [".", "child"].into_iter().enumerate() {
            assert!(!reply.add(
                INodeNo(2),
                offset as u64 + 1,
                name,
                &TTL,
                &attr(),
                Generation(1)
            ));
        }
        reply.ok();
    }
}

fn dispatch(
    fs: &Probe,
    opcode: u32,
    body: &[u8],
    mapping: FilesystemMapping,
) -> mpsc::Receiver<Vec<u8>> {
    let packet = packet(opcode, body);
    let bytes = packet.as_slice().as_bytes();
    let original = bytes.to_vec();
    let (sender, rx) = sender();
    RequestWithSender::new(sender, bytes)
        .unwrap()
        .with_mapping(mapping)
        .dispatch(&DispatchContext {
            filesystem: fs,
            allowed: SessionACL::All,
            session_owner: Uid::from_raw(0),
            thread_name: "mapping-test",
        });
    assert_eq!(bytes, original);
    rx
}

fn receive(rx: mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    let bytes = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(i32::from_ne_bytes(bytes[4..8].try_into().unwrap()), 0);
    assert_eq!(u64::from_ne_bytes(bytes[8..16].try_into().unwrap()), 123);
    bytes
}

fn ownership(bytes: &[u8], attr_offset: usize) -> (u32, u32) {
    let read = |offset| {
        u32::from_ne_bytes(
            bytes[attr_offset + offset..attr_offset + offset + 4]
                .try_into()
                .unwrap(),
        )
    };
    (
        read(offset_of!(abi::fuse_attr, uid)),
        read(offset_of!(abi::fuse_attr, gid)),
    )
}

#[test]
fn translates_all_attribute_reply_encoders() {
    for mapping in [FilesystemMapping::default(), MAPPING] {
        let fs = Probe::new(mapping);
        let expected = (
            mapping.uid.to_client(attr().uid),
            mapping.gid.to_client(attr().gid),
        );
        for name in [b"entry\0".as_slice(), b"ttls\0"] {
            let bytes = receive(dispatch(&fs, 1, name, mapping));
            assert_eq!(
                ownership(&bytes, 16 + offset_of!(abi::fuse_entry_out, attr)),
                expected
            );
        }
        for name in [b"create\0".as_slice(), b"passthrough\0"] {
            let mut body = vec![0; size_of::<abi::fuse_create_in>()];
            body.extend_from_slice(name);
            let bytes = receive(dispatch(&fs, 35, &body, mapping));
            assert_eq!(
                ownership(&bytes, 16 + offset_of!(abi::fuse_entry_out, attr)),
                expected
            );
        }
        let mut body = vec![0; size_of::<abi::fuse_read_in>()];
        let size = offset_of!(abi::fuse_read_in, size);
        body[size..size + 4].copy_from_slice(&4096u32.to_ne_bytes());
        let bytes = receive(dispatch(&fs, 44, &body, mapping));
        let mut offset = 16;
        for name in [".", "child"] {
            assert_eq!(
                ownership(&bytes, offset + offset_of!(abi::fuse_entry_out, attr)),
                expected
            );
            offset +=
                (size_of::<abi::fuse_entry_out>() + size_of::<abi::fuse_dirent>() + name.len())
                    .next_multiple_of(8);
        }
        assert_eq!(offset, bytes.len());
    }
}

#[test]
fn setattr_only_maps_valid_ownership_arguments() {
    let fs = Probe::new(MAPPING);
    for (valid, expected) in [
        (0u32, (None, None)),
        (2, (Some(100_007), None)),
        (4, (None, Some(0))),
        (6, (Some(100_007), Some(0))),
    ] {
        let mut body = vec![0; size_of::<abi::fuse_setattr_in>()];
        body[..4].copy_from_slice(&valid.to_ne_bytes());
        let uid = offset_of!(abi::fuse_setattr_in, uid);
        body[uid..uid + 4].copy_from_slice(&8u32.to_ne_bytes());
        let bytes = receive(dispatch(&fs, 4, &body, MAPPING));
        assert_eq!(fs.ownership.lock().unwrap().take(), Some(expected));
        assert_eq!(
            ownership(&bytes, 16 + offset_of!(abi::fuse_attr_out, attr)),
            (7, 19)
        );
    }
}

#[test]
fn deferred_replies_own_their_mapping() {
    let fs = Probe::new(MAPPING);
    let rx = dispatch(&fs, 3, &[0; 16], MAPPING);
    let reply = fs.deferred.lock().unwrap().take().unwrap();
    drop(fs);
    let other = Probe::new(FilesystemMapping::default());
    let identity_rx = dispatch(&other, 3, &[0; 16], FilesystemMapping::default());
    std::thread::spawn(move || reply.attr(&TTL, &attr()))
        .join()
        .unwrap();
    other
        .deferred
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .attr(&TTL, &attr());
    assert_eq!(
        ownership(&receive(rx), 16 + offset_of!(abi::fuse_attr_out, attr)),
        (7, 19)
    );
    assert_eq!(
        ownership(
            &receive(identity_rx),
            16 + offset_of!(abi::fuse_attr_out, attr)
        ),
        (100_006, 200_018)
    );
}

#[test]
fn session_acl_uses_client_credentials() {
    let fs = Probe::new(MAPPING);
    let packet = packet(1, b"entry\0");
    for (owner, allowed) in [(7, true), (100_006, false)] {
        let (sender, rx) = sender();
        RequestWithSender::new(sender, packet.as_slice().as_bytes())
            .unwrap()
            .with_mapping(MAPPING)
            .dispatch(&DispatchContext {
                filesystem: &fs,
                allowed: SessionACL::Owner,
                session_owner: Uid::from_raw(owner),
                thread_name: "mapping-test",
            });
        let bytes = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            i32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
            if allowed { 0 } else { -libc::EACCES }
        );
    }
}

#[test]
fn init_credentials_and_default_identity() {
    let mut body = vec![0; size_of::<abi::fuse_init_in>()];
    body[..4].copy_from_slice(&7u32.to_ne_bytes());
    body[4..8].copy_from_slice(&31u32.to_ne_bytes());
    let init_packet = packet(26, &body);
    for mapping in [FilesystemMapping::default(), MAPPING] {
        let mut fs = Probe::new(mapping);
        let (sender, rx) = sender();
        let result = if mapping == FilesystemMapping::default() {
            crate::handshake_request(&mut fs, sender, init_packet.as_slice().as_bytes())
        } else {
            crate::handshake_request_with_mapping(
                &mut fs,
                sender,
                init_packet.as_slice().as_bytes(),
                mapping,
            )
        };
        assert!(matches!(result.unwrap(), HandshakeOutcome::Complete { .. }));
        receive(rx);
    }
    let fs = Probe::new(FilesystemMapping::default());
    let packet = packet(1, b"entry\0");
    let (sender, rx) = sender();
    RequestWithSender::new(sender, packet.as_slice().as_bytes())
        .unwrap()
        .dispatch(&DispatchContext {
            filesystem: &fs,
            allowed: SessionACL::All,
            session_owner: Uid::from_raw(0),
            thread_name: "mapping-test",
        });
    assert_eq!(
        ownership(&receive(rx), 16 + offset_of!(abi::fuse_entry_out, attr)),
        (100_006, 200_018)
    );
}
