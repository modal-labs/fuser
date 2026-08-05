//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
use log::{info, warn};
use nix::unistd::geteuid;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::{io, ops::DerefMut};

use crate::ll::fuse_abi as abi;
use crate::request::Request;
use crate::Filesystem;
use crate::MountOption;
use crate::{channel::Channel, mnt::Mount};
#[cfg(feature = "abi-7-11")]
use crate::{channel::ChannelSender, notify::Notifier};

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// Size of the buffer for reading a request from the kernel. Since the kernel may send
/// up to MAX_WRITE_SIZE bytes in a write request, we use that value plus some extra space.
const BUFFER_SIZE: usize = MAX_WRITE_SIZE + 4096;

/// Access control policy for filesystem requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionACL {
    /// Allow all users.
    All,
    /// Allow root and the session owner.
    RootAndOwner,
    /// Allow only the session owner.
    Owner,
}

/// Transport-agnostic filesystem session state used by [`Request::dispatch`].
///
/// This struct holds the filesystem implementation and protocol state needed to
/// dispatch FUSE requests. It is decoupled from any specific transport (e.g.
/// `/dev/fuse`, virtiofs) so that it can be used with any source of raw FUSE
/// request bytes.
#[derive(Debug)]
pub struct FilesystemSession<FS: Filesystem> {
    /// Filesystem operation implementations.
    pub filesystem: FS,
    /// Whether to restrict access to owner, root + owner, or unrestricted.
    pub allowed: SessionACL,
    /// User that launched the fuser process.
    pub session_owner: u32,
    /// FUSE protocol major version.
    pub proto_major: u32,
    /// FUSE protocol minor version.
    pub proto_minor: u32,
    /// True if the filesystem is initialized (init operation done).
    pub initialized: bool,
    /// True if the filesystem was destroyed (destroy operation done).
    pub destroyed: bool,
    /// Size of the request buffer, lowered from BUFFER_SIZE after FUSE_INIT negotiation.
    pub buffer_size: usize,
}

impl<FS: Filesystem> Drop for FilesystemSession<FS> {
    fn drop(&mut self) {
        if !self.destroyed {
            self.filesystem.destroy();
            self.destroyed = true;
        }
    }
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem session state (filesystem impl + protocol state).
    pub(crate) inner: FilesystemSession<FS>,
    /// Communication channel to the kernel driver
    ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: Arc<Mutex<Option<Mount>>>,
    /// Mount point
    mountpoint: PathBuf,
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    pub fn new<P: AsRef<Path>>(
        filesystem: FS,
        mountpoint: P,
        options: &[MountOption],
    ) -> io::Result<Session<FS>> {
        let mountpoint = mountpoint.as_ref();
        info!("Mounting {}", mountpoint.display());
        // If AutoUnmount is requested, but not AllowRoot or AllowOther we enforce the ACL
        // ourself and implicitly set AllowOther because fusermount needs allow_root or allow_other
        // to handle the auto_unmount option
        let (file, mount) = if options.contains(&MountOption::AutoUnmount)
            && !(options.contains(&MountOption::AllowRoot)
                || options.contains(&MountOption::AllowOther))
        {
            warn!("Given auto_unmount without allow_root or allow_other; adding allow_other, with userspace permission handling");
            let mut modified_options = options.to_vec();
            modified_options.push(MountOption::AllowOther);
            Mount::new(mountpoint, &modified_options)?
        } else {
            Mount::new(mountpoint, options)?
        };

        let ch = Channel::new(file);
        let allowed = if options.contains(&MountOption::AllowRoot) {
            SessionACL::RootAndOwner
        } else if options.contains(&MountOption::AllowOther) {
            SessionACL::All
        } else {
            SessionACL::Owner
        };

        Ok(Session {
            inner: FilesystemSession {
                filesystem,
                allowed,
                session_owner: geteuid().as_raw(),
                proto_major: 0,
                proto_minor: 0,
                initialized: false,
                destroyed: false,
                buffer_size: BUFFER_SIZE,
            },
            ch,
            mount: Arc::new(Mutex::new(Some(mount))),
            mountpoint: mountpoint.to_owned(),
        })
    }

    /// Return path of the mounted filesystem
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    pub fn run(&mut self) -> io::Result<()> {
        event_loop(&self.ch, &mut self.inner, false)
    }

    /// Unmount the filesystem
    pub fn unmount(&mut self) {
        drop(std::mem::take(&mut *self.mount.lock().unwrap()));
    }

    /// Returns a thread-safe object that can be used to unmount the Filesystem
    pub fn unmount_callable(&mut self) -> SessionUnmounter {
        SessionUnmounter {
            mount: self.mount.clone(),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.ch.sender())
    }
}

impl<FS: Filesystem + Clone + Send + 'static> Session<FS> {
    /// Run the session with `n_threads` event-loop threads, each reading and
    /// dispatching kernel requests independently. This parallelizes the
    /// kernel-to-userspace request path (most importantly the payload copy of
    /// WRITE requests), which is serialized when a single loop is used.
    ///
    /// Requests are processed on a single thread until `FUSE_INIT` completes;
    /// the remaining event-loop threads are then started with the negotiated
    /// protocol state. Each thread operates on its own clone of the
    /// filesystem, so shared state must live behind `Arc`s or similar inside
    /// the [`Filesystem`] implementation. On drop, `destroy` may be invoked
    /// once per clone.
    ///
    /// If `clone_fd` is true, each additional thread gets its own `/dev/fuse`
    /// fd via `FUSE_DEV_IOC_CLONE` (Linux 4.5+) for independent kernel-side
    /// queuing; otherwise all threads share the session fd.
    pub fn run_mt(&mut self, n_threads: usize, clone_fd: bool) -> io::Result<()> {
        // Process requests single-threaded until FUSE_INIT completes, so the
        // worker sessions can copy the negotiated protocol state.
        event_loop(&self.ch, &mut self.inner, true)?;
        if !self.inner.initialized {
            // The kernel closed the session before INIT; nothing more to do.
            return Ok(());
        }

        let mut workers: Vec<JoinHandle<io::Result<()>>> = Vec::new();
        for _ in 1..n_threads {
            let ch = if clone_fd {
                #[cfg(target_os = "linux")]
                {
                    self.ch.clone_fd()?
                }
                #[cfg(not(target_os = "linux"))]
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "clone_fd is only supported on Linux",
                    ));
                }
            } else {
                self.ch.clone()
            };
            let mut worker = FilesystemSession {
                filesystem: self.inner.filesystem.clone(),
                allowed: self.inner.allowed,
                session_owner: self.inner.session_owner,
                proto_major: self.inner.proto_major,
                proto_minor: self.inner.proto_minor,
                initialized: true,
                destroyed: false,
                buffer_size: self.inner.buffer_size,
            };
            workers.push(thread::spawn(move || event_loop(&ch, &mut worker, false)));
        }

        let result = event_loop(&self.ch, &mut self.inner, false);
        for worker in workers {
            match worker.join() {
                Ok(res) => res?,
                Err(_) => {
                    return Err(io::Error::other("FUSE event-loop thread panicked"));
                }
            }
        }
        result
    }
}

/// Read-dispatch loop for a single event-loop thread. If `until_initialized`
/// is true, the loop returns after `FUSE_INIT` has been processed.
fn event_loop<FS: Filesystem>(
    ch: &Channel,
    se: &mut FilesystemSession<FS>,
    until_initialized: bool,
) -> io::Result<()> {
    // Buffer for receiving requests from the kernel. Only one is allocated and
    // it is reused immediately after dispatching to conserve memory and allocations.
    let mut buffer = vec![0; se.buffer_size.min(BUFFER_SIZE)];
    loop {
        if until_initialized && se.initialized {
            break;
        }
        // After FUSE_INIT, lower the buffer to the negotiated max_write size before
        // recomputing the aligned sub-buffer.
        if se.buffer_size < buffer.len() {
            buffer.resize(se.buffer_size, 0);
            buffer.shrink_to_fit();
        }
        // Recompute aligned sub-buffer each iteration so we can resize the
        // buffer after FUSE_INIT negotiation.
        let buf = aligned_sub_buf(
            buffer.deref_mut(),
            std::mem::align_of::<abi::fuse_in_header>(),
        );
        // Read the next request from the given channel to kernel driver
        // The kernel driver makes sure that we get exactly one request per read
        match ch.receive(buf) {
            Ok(size) => match Request::new(&buf[..size]) {
                // Dispatch request
                Some(req) => req.dispatch(se, ch.sender()),
                // Quit loop on illegal request
                None => break,
            },
            Err(err) => match err.raw_os_error() {
                // Operation interrupted. Accordingly to FUSE, this is safe to retry
                Some(ENOENT) => continue,
                // Interrupted system call, retry
                Some(EINTR) => continue,
                // Explicitly try again
                Some(EAGAIN) => continue,
                // Filesystem was unmounted, quit the loop
                Some(ENODEV) => break,
                // Unhandled error
                _ => return Err(err),
            },
        }
    }
    Ok(())
}

#[derive(Debug)]
/// A thread-safe object that can be used to unmount a Filesystem
pub struct SessionUnmounter {
    mount: Arc<Mutex<Option<Mount>>>,
}

impl SessionUnmounter {
    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        drop(std::mem::take(&mut *self.mount.lock().unwrap()));
        Ok(())
    }
}

fn aligned_sub_buf(buf: &mut [u8], alignment: usize) -> &mut [u8] {
    let off = alignment - (buf.as_ptr() as usize) % alignment;
    if off == alignment {
        buf
    } else {
        &mut buf[off..]
    }
}

impl<FS: 'static + Filesystem + Send> Session<FS> {
    /// Run the session loop in a background thread
    pub fn spawn(self) -> io::Result<BackgroundSession> {
        BackgroundSession::new(self)
    }
}

impl<FS: 'static + Filesystem + Clone + Send> Session<FS> {
    /// Run a multi-threaded session loop (see [`Session::run_mt`]) in
    /// background threads.
    pub fn spawn_mt(self, n_threads: usize, clone_fd: bool) -> io::Result<BackgroundSession> {
        BackgroundSession::new_mt(self, n_threads, clone_fd)
    }
}

impl<FS: Filesystem> Drop for Session<FS> {
    fn drop(&mut self) {
        info!("Unmounted {}", self.mountpoint().display());
    }
}

/// The background session data structure
pub struct BackgroundSession {
    /// Path of the mounted filesystem
    pub mountpoint: PathBuf,
    /// Thread guard of the background session
    pub guard: JoinHandle<io::Result<()>>,
    /// Object for creating Notifiers for client use
    #[cfg(feature = "abi-7-11")]
    sender: ChannelSender,
    /// Ensures the filesystem is unmounted when the session ends
    _mount: Mount,
}

impl BackgroundSession {
    /// Create a new background session for the given session by running its
    /// session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub fn new<FS: Filesystem + Send + 'static>(se: Session<FS>) -> io::Result<BackgroundSession> {
        let mountpoint = se.mountpoint().to_path_buf();
        #[cfg(feature = "abi-7-11")]
        let sender = se.ch.sender();
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut *se.mount.lock().unwrap());
        let mount = mount.ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))?;
        let guard = thread::spawn(move || {
            let mut se = se;
            se.run()
        });
        Ok(BackgroundSession {
            mountpoint,
            guard,
            #[cfg(feature = "abi-7-11")]
            sender,
            _mount: mount,
        })
    }

    /// Like [`BackgroundSession::new`], but runs a multi-threaded session
    /// loop (see [`Session::run_mt`]).
    pub fn new_mt<FS: Filesystem + Clone + Send + 'static>(
        se: Session<FS>,
        n_threads: usize,
        clone_fd: bool,
    ) -> io::Result<BackgroundSession> {
        let mountpoint = se.mountpoint().to_path_buf();
        #[cfg(feature = "abi-7-11")]
        let sender = se.ch.sender();
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut *se.mount.lock().unwrap());
        let mount = mount.ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))?;
        let guard = thread::spawn(move || {
            let mut se = se;
            se.run_mt(n_threads, clone_fd)
        });
        Ok(BackgroundSession {
            mountpoint,
            guard,
            #[cfg(feature = "abi-7-11")]
            sender,
            _mount: mount,
        })
    }
    /// Unmount the filesystem and join the background thread.
    pub fn join(self) {
        let Self {
            mountpoint: _,
            guard,
            #[cfg(feature = "abi-7-11")]
                sender: _,
            _mount,
        } = self;
        drop(_mount);
        guard.join().unwrap().unwrap();
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.sender.clone())
    }
}

// replace with #[derive(Debug)] if Debug ever gets implemented for
// thread_scoped::JoinGuard
impl fmt::Debug for BackgroundSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "BackgroundSession {{ mountpoint: {:?}, guard: JoinGuard<()> }}",
            self.mountpoint
        )
    }
}
