use std::{fs::File, io, os::unix::prelude::AsRawFd, sync::Arc};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

use libc::{c_int, c_void, size_t};

use crate::reply::ReplySender;

/// `FUSE_DEV_IOC_CLONE`: `_IOR(229, 0, uint32_t)`.
#[cfg(target_os = "linux")]
const FUSE_DEV_IOC_CLONE: libc::c_ulong = 0x8004_E500;

/// A raw communication channel to the FUSE kernel driver
#[derive(Clone, Debug)]
pub struct Channel(Arc<File>);

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<File>) -> Self {
        Self(device)
    }

    /// Receives data up to the capacity of the given buffer (can block).
    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let rc = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                buffer.as_ptr() as *mut c_void,
                buffer.len() as size_t,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }

    /// Clone the FUSE session file descriptor via `FUSE_DEV_IOC_CLONE`,
    /// returning a new channel with its own `/dev/fuse` fd attached to the
    /// same session. Each fd has independent kernel-side request queuing,
    /// which avoids contention when multiple threads read requests.
    ///
    /// Requires Linux 4.5+.
    #[cfg(target_os = "linux")]
    pub fn clone_fd(&self) -> io::Result<Self> {
        let clone = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/fuse")?;
        let source_fd: u32 = self.0.as_raw_fd() as u32;
        let rc = unsafe { libc::ioctl(clone.as_raw_fd(), FUSE_DEV_IOC_CLONE, &source_fd) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(Arc::new(clone)))
    }

    /// Returns a sender object for this channel. The sender object can be
    /// used to send to the channel. Multiple sender objects can be used
    /// and they can safely be sent to other threads.
    pub fn sender(&self) -> ChannelSender {
        // Since write/writev syscalls are threadsafe, we can simply create
        // a sender by using the same file and use it in other threads.
        ChannelSender(self.0.clone())
    }
}

#[derive(Clone, Debug)]
pub struct ChannelSender(Arc<File>);

impl ReplySender for ChannelSender {
    fn send(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        let rc = unsafe {
            libc::writev(
                self.0.as_raw_fd(),
                bufs.as_ptr() as *const libc::iovec,
                bufs.len() as c_int,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            debug_assert_eq!(bufs.iter().map(|b| b.len()).sum::<usize>(), rc as usize);
            Ok(())
        }
    }
}
