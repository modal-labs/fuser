use crate::FilesystemMapping;
use crate::ll;
use crate::ll::fuse_abi::fuse_in_header;

/// FUSE request parameters.
#[derive(Debug)]
pub struct Request {
    header: fuse_in_header,
}

impl Request {
    pub(crate) fn from_header(header: &fuse_in_header, mapping: FilesystemMapping) -> Self {
        Self {
            header: fuse_in_header {
                uid: mapping.uid.to_filesystem(header.uid),
                gid: mapping.gid.to_filesystem(header.gid),
                ..*header
            },
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
