use crate::FilesystemMapping;
use crate::channel::ChannelSender;
use crate::ll;
use crate::ll::fuse_abi::fuse_in_header;

#[derive(Clone, Debug)]
pub(crate) enum Backlog {
    Known(bool),
    Poll(ChannelSender),
}

/// FUSE request parameters.
#[derive(Debug)]
pub struct Request {
    header: fuse_in_header,
    backlog: Backlog,
}

impl Request {
    pub(crate) fn from_header(
        header: &fuse_in_header,
        mapping: FilesystemMapping,
        backlog: Backlog,
    ) -> Self {
        Self {
            header: fuse_in_header {
                uid: mapping.uid.to_filesystem(header.uid),
                gid: mapping.gid.to_filesystem(header.gid),
                ..*header
            },
            backlog,
        }
    }

    /// Returns whether more requests are currently queued on the transport. Each call
    /// checks the transport, so filesystems should call it right before the decision
    /// it informs. Filesystems can use it to decide whether blocking briefly on the
    /// request thread delays other requests.
    #[inline]
    pub fn has_backlog(&self) -> bool {
        match &self.backlog {
            Backlog::Known(backlog) => *backlog,
            Backlog::Poll(channel) => channel.has_pending(),
        }
    }

    /// Returns the unique identifier of this request
    #[inline]
    pub fn unique(&self) -> ll::RequestId {
        ll::RequestId(self.header.unique)
    }

    /// Returns the uid of this request
    #[inline]
    pub fn uid(&self) -> u32 {
        self.header.uid
    }

    /// Returns the gid of this request
    #[inline]
    pub fn gid(&self) -> u32 {
        self.header.gid
    }

    /// Returns the pid of this request
    #[inline]
    pub fn pid(&self) -> u32 {
        self.header.pid
    }
}
