//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.
//!
//! TODO: This module is meant to go away soon in favor of `ll::Request`.

use crate::ll::{fuse_abi as abi, Errno, Operation, RequestError, Response};
use log::{debug, error, warn};
use std::convert::TryFrom;
#[cfg(feature = "abi-7-28")]
use std::convert::TryInto;
use std::fmt;
use std::path::Path;

use crate::ll::Request as _;
#[cfg(feature = "abi-7-21")]
use crate::reply::ReplyDirectoryPlus;
use crate::reply::{Reply, ReplyDirectory, ReplySender};
use crate::session::{FilesystemSession, SessionACL};
use crate::Filesystem;
use crate::{ll, KernelConfig};

/// Request data structure
pub struct Request<'a> {
    /// Request raw data
    #[allow(unused)]
    data: &'a [u8],
    /// Parsed request
    request: ll::AnyRequest<'a>,
}

impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("data_len", &self.data.len())
            .field("request", &self.request)
            .finish()
    }
}

impl<'a> Request<'a> {
    /// Create a new request from the given data
    pub fn new(data: &'a [u8]) -> Option<Request<'a>> {
        let request = match ll::AnyRequest::try_from(data) {
            Ok(request) => request,
            Err(err) => {
                error!("{}", err);
                return None;
            }
        };

        Some(Self { data, request })
    }

    /// Dispatch request to the given filesystem session.
    ///
    /// This parses the FUSE opcode, calls the appropriate [`Filesystem`] method,
    /// and sends back the reply through the [`ReplySender`].
    pub fn dispatch<FS: Filesystem>(
        &self,
        se: &mut FilesystemSession<FS>,
        sender: impl ReplySender,
    ) {
        debug!("{}", self.request);
        let unique = self.request.unique();

        let (resp, sender) = match self.dispatch_req(se, sender) {
            Ok(Some((resp, sender))) => (resp, sender),
            Ok(None) => return,
            Err((errno, sender)) => (self.request.reply_err(errno), sender),
        };
        let res = resp.with_iovec(unique, |iov| sender.send(iov));

        if let Err(err) = res {
            warn!("Request {:?}: Failed to send reply: {}", unique, err)
        }
    }

    fn dispatch_req<FS: Filesystem, RS: ReplySender>(
        &self,
        se: &mut FilesystemSession<FS>,
        sender: RS,
    ) -> Result<Option<(Response<'_>, RS)>, (Errno, RS)> {
        let op = match self.request.operation() {
            Ok(op) => op,
            Err(_) => {
                return Err((Errno::ENOSYS, sender));
            }
        };
        // Implement allow_root & access check for auto_unmount
        if (se.allowed == SessionACL::RootAndOwner
            && self.request.uid() != se.session_owner
            && self.request.uid() != 0)
            || (se.allowed == SessionACL::Owner && self.request.uid() != se.session_owner)
        {
            #[cfg(feature = "abi-7-21")]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::ReadDirPlus(_)
                    | ll::Operation::BatchForget(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err((Errno::EACCES, sender));
                    }
                }
            }
            #[cfg(all(feature = "abi-7-16", not(feature = "abi-7-21")))]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::BatchForget(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err((Errno::EACCES, sender));
                    }
                }
            }
            #[cfg(not(feature = "abi-7-16"))]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err((Errno::EACCES, sender));
                    }
                }
            }
        }
        match op {
            // Filesystem initialization
            ll::Operation::Init(x) => {
                // We don't support ABI versions before 7.6
                let v = x.version();
                if v < ll::Version(7, 6) {
                    error!("Unsupported FUSE ABI version {}", v);
                    return Err((Errno::EPROTO, sender));
                }
                // Remember ABI version supported by kernel
                se.proto_major = v.major();
                se.proto_minor = v.minor();

                let mut config = KernelConfig::new(x.capabilities(), x.max_readahead());
                // Call filesystem init method and give it a chance to return an error
                if let Err(e) = se.filesystem.init(self, &mut config) {
                    return Err((Errno::EIO, sender));
                }

                // Reply with our desired version and settings. If the kernel supports a
                // larger major version, it'll re-send a matching init message. If it
                // supports only lower major versions, we replied with an error above.
                debug!(
                    "INIT response: ABI {}.{}, flags {:#x}, max readahead {}, max write {}",
                    abi::FUSE_KERNEL_VERSION,
                    abi::FUSE_KERNEL_MINOR_VERSION,
                    x.capabilities() & config.requested,
                    config.max_readahead,
                    config.max_write
                );
                se.initialized = true;
                se.buffer_size = config.max_write as usize + 4096;
                return Ok(Some((x.reply(&config), sender)));
            }
            // Any operation is invalid before initialization
            _ if !se.initialized => {
                warn!("Ignoring FUSE operation before init: {}", self.request);
                return Err((Errno::EIO, sender));
            }
            // Filesystem destroyed
            ll::Operation::Destroy(x) => {
                se.filesystem.destroy();
                se.destroyed = true;
                return Ok(Some((x.reply(), sender)));
            }
            // Any operation is invalid after destroy
            _ if se.destroyed => {
                warn!("Ignoring FUSE operation after destroy: {}", self.request);
                return Err((Errno::EIO, sender));
            }

            ll::Operation::Interrupt(_) => {
                // TODO: handle FUSE_INTERRUPT
                return Err((Errno::ENOSYS, sender));
            }

            ll::Operation::Lookup(x) => {
                se.filesystem.lookup(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(sender),
                );
            }
            ll::Operation::Forget(x) => {
                se.filesystem
                    .forget(self, self.request.nodeid().into(), x.nlookup()); // no reply
            }
            ll::Operation::GetAttr(_attr) => {
                #[cfg(feature = "abi-7-9")]
                se.filesystem.getattr(
                    self,
                    self.request.nodeid().into(),
                    _attr.file_handle().map(|fh| fh.into()),
                    self.reply(sender),
                );

                // Pre-abi-7-9 does not support providing a file handle.
                #[cfg(not(feature = "abi-7-9"))]
                se.filesystem
                    .getattr(self, self.request.nodeid().into(), None, self.reply(sender));
            }
            ll::Operation::SetAttr(x) => {
                se.filesystem.setattr(
                    self,
                    self.request.nodeid().into(),
                    x.mode(),
                    x.uid(),
                    x.gid(),
                    x.size(),
                    x.atime(),
                    x.mtime(),
                    x.ctime(),
                    x.file_handle().map(|fh| fh.into()),
                    x.crtime(),
                    x.chgtime(),
                    x.bkuptime(),
                    x.flags(),
                    self.reply(sender),
                );
            }
            ll::Operation::ReadLink(_) => {
                se.filesystem
                    .readlink(self, self.request.nodeid().into(), self.reply(sender));
            }
            ll::Operation::MkNod(x) => {
                se.filesystem.mknod(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.rdev(),
                    self.reply(sender),
                );
            }
            ll::Operation::MkDir(x) => {
                se.filesystem.mkdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    self.reply(sender),
                );
            }
            ll::Operation::Unlink(x) => {
                se.filesystem.unlink(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(sender),
                );
            }
            ll::Operation::RmDir(x) => {
                se.filesystem.rmdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(sender),
                );
            }
            ll::Operation::SymLink(x) => {
                se.filesystem.symlink(
                    self,
                    self.request.nodeid().into(),
                    x.link_name().as_ref(),
                    Path::new(x.target()),
                    self.reply(sender),
                );
            }
            ll::Operation::Rename(x) => {
                se.filesystem.rename(
                    self,
                    self.request.nodeid().into(),
                    x.src().name.as_ref(),
                    x.dest().dir.into(),
                    x.dest().name.as_ref(),
                    0,
                    self.reply(sender),
                );
            }
            ll::Operation::Link(x) => {
                se.filesystem.link(
                    self,
                    x.inode_no().into(),
                    self.request.nodeid().into(),
                    x.dest().name.as_ref(),
                    self.reply(sender),
                );
            }
            ll::Operation::Open(x) => {
                se.filesystem.open(
                    self,
                    self.request.nodeid().into(),
                    x.flags(),
                    self.reply(sender),
                );
            }
            ll::Operation::Read(x) => {
                se.filesystem.read(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.size(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into()),
                    self.reply(sender),
                );
            }
            ll::Operation::Write(x) => {
                se.filesystem.write(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.data(),
                    x.write_flags(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into()),
                    self.reply(sender),
                );
            }
            ll::Operation::Flush(x) => {
                se.filesystem.flush(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    self.reply(sender),
                );
            }
            ll::Operation::Release(x) => {
                se.filesystem.release(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    x.lock_owner().map(|x| x.into()),
                    x.flush(),
                    self.reply(sender),
                );
            }
            ll::Operation::FSync(x) => {
                se.filesystem.fsync(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(sender),
                );
            }
            ll::Operation::OpenDir(x) => {
                se.filesystem.opendir(
                    self,
                    self.request.nodeid().into(),
                    x.flags(),
                    self.reply(sender),
                );
            }
            ll::Operation::ReadDir(x) => {
                se.filesystem.readdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectory::new(self.request.unique().into(), sender, x.size() as usize),
                );
            }
            ll::Operation::ReleaseDir(x) => {
                se.filesystem.releasedir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    self.reply(sender),
                );
            }
            ll::Operation::FSyncDir(x) => {
                se.filesystem.fsyncdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(sender),
                );
            }
            ll::Operation::StatFs(_) => {
                se.filesystem
                    .statfs(self, self.request.nodeid().into(), self.reply(sender));
            }
            ll::Operation::SetXAttr(x) => {
                se.filesystem.setxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.value(),
                    x.flags(),
                    x.position(),
                    self.reply(sender),
                );
            }
            ll::Operation::GetXAttr(x) => {
                se.filesystem.getxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.size_u32(),
                    self.reply(sender),
                );
            }
            ll::Operation::ListXAttr(x) => {
                se.filesystem.listxattr(
                    self,
                    self.request.nodeid().into(),
                    x.size(),
                    self.reply(sender),
                );
            }
            ll::Operation::RemoveXAttr(x) => {
                se.filesystem.removexattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    self.reply(sender),
                );
            }
            ll::Operation::Access(x) => {
                se.filesystem.access(
                    self,
                    self.request.nodeid().into(),
                    x.mask(),
                    self.reply(sender),
                );
            }
            ll::Operation::Create(x) => {
                se.filesystem.create(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.flags(),
                    self.reply(sender),
                );
            }
            ll::Operation::GetLk(x) => {
                se.filesystem.getlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    self.reply(sender),
                );
            }
            ll::Operation::SetLk(x) => {
                se.filesystem.setlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    false,
                    self.reply(sender),
                );
            }
            ll::Operation::SetLkW(x) => {
                se.filesystem.setlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    true,
                    self.reply(sender),
                );
            }
            ll::Operation::BMap(x) => {
                se.filesystem.bmap(
                    self,
                    self.request.nodeid().into(),
                    x.block_size(),
                    x.block(),
                    self.reply(sender),
                );
            }

            #[cfg(feature = "abi-7-11")]
            ll::Operation::IoCtl(x) => {
                if x.unrestricted() {
                    return Err((Errno::ENOSYS, sender));
                } else {
                    se.filesystem.ioctl(
                        self,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.flags(),
                        x.command(),
                        x.in_data(),
                        x.out_size(),
                        self.reply(sender),
                    );
                }
            }
            #[cfg(feature = "abi-7-11")]
            ll::Operation::Poll(x) => {
                se.filesystem.poll(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.kernel_handle(),
                    x.events(),
                    x.flags(),
                    self.reply(sender),
                );
            }
            #[cfg(feature = "abi-7-15")]
            ll::Operation::NotifyReply(_) => {
                // TODO: handle FUSE_NOTIFY_REPLY
                return Err((Errno::ENOSYS, sender));
            }
            #[cfg(feature = "abi-7-16")]
            ll::Operation::BatchForget(x) => {
                se.filesystem.batch_forget(self, x.nodes()); // no reply
            }
            #[cfg(feature = "abi-7-19")]
            ll::Operation::FAllocate(x) => {
                se.filesystem.fallocate(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.len(),
                    x.mode(),
                    self.reply(sender),
                );
            }
            #[cfg(feature = "abi-7-21")]
            ll::Operation::ReadDirPlus(x) => {
                se.filesystem.readdirplus(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectoryPlus::new(
                        self.request.unique().into(),
                        sender,
                        x.size() as usize,
                    ),
                );
            }
            #[cfg(feature = "abi-7-23")]
            ll::Operation::Rename2(x) => {
                se.filesystem.rename(
                    self,
                    x.from().dir.into(),
                    x.from().name.as_ref(),
                    x.to().dir.into(),
                    x.to().name.as_ref(),
                    x.flags(),
                    self.reply(sender),
                );
            }
            #[cfg(feature = "abi-7-24")]
            ll::Operation::Lseek(x) => {
                se.filesystem.lseek(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.whence(),
                    self.reply(sender),
                );
            }
            #[cfg(feature = "abi-7-28")]
            ll::Operation::CopyFileRange(x) => {
                let (i, o) = (x.src(), x.dest());
                se.filesystem.copy_file_range(
                    self,
                    i.inode.into(),
                    i.file_handle.into(),
                    i.offset,
                    o.inode.into(),
                    o.file_handle.into(),
                    o.offset,
                    x.len(),
                    x.flags().try_into().unwrap(),
                    self.reply(sender),
                );
            }
            #[cfg(target_os = "macos")]
            ll::Operation::SetVolName(x) => {
                se.filesystem.setvolname(self, x.name(), self.reply(sender));
            }
            #[cfg(target_os = "macos")]
            ll::Operation::GetXTimes(_) => {
                se.filesystem
                    .getxtimes(self, self.request.nodeid().into(), self.reply(sender));
            }
            #[cfg(target_os = "macos")]
            ll::Operation::Exchange(x) => {
                se.filesystem.exchange(
                    self,
                    x.from().dir.into(),
                    x.from().name.as_ref(),
                    x.to().dir.into(),
                    x.to().name.as_ref(),
                    x.options(),
                    self.reply(sender),
                );
            }

            #[cfg(feature = "abi-7-12")]
            ll::Operation::CuseInit(_) => {
                // TODO: handle CUSE_INIT
                return Err((Errno::ENOSYS, sender));
            }
        }
        Ok(None)
    }

    /// Create a reply object for this request that can be passed to the filesystem
    /// implementation and makes sure that a request is replied exactly once
    fn reply<T: Reply>(&self, sender: impl ReplySender) -> T {
        Reply::new(self.request.unique().into(), sender)
    }

    /// Returns the unique identifier of this request
    #[inline]
    pub fn unique(&self) -> u64 {
        self.request.unique().into()
    }

    /// Returns the uid of this request
    #[inline]
    pub fn uid(&self) -> u32 {
        self.request.uid()
    }

    /// Returns the gid of this request
    #[inline]
    pub fn gid(&self) -> u32 {
        self.request.gid()
    }

    /// Returns the pid of this request
    #[inline]
    pub fn pid(&self) -> u32 {
        self.request.pid()
    }
}
