//! Translation between client-visible and filesystem-visible identifiers.

#[cfg(test)]
mod protocol_tests;

/// A range of identifiers translated between a client and a filesystem.
///
/// IDs outside the configured range pass through unchanged in each direction.
/// The default mapping is identity. Identity fallback means this is not
/// necessarily a bijection over all IDs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdMap {
    client_base: u32,
    filesystem_base: u32,
    count: u32,
}

impl IdMap {
    /// Map `count` IDs starting at each base, with exclusive upper bounds.
    ///
    /// # Panics
    /// Panics if either base plus `count` overflows a `u32`.
    pub const fn new(client_base: u32, filesystem_base: u32, count: u32) -> Self {
        assert!(client_base.checked_add(count).is_some());
        assert!(filesystem_base.checked_add(count).is_some());
        Self {
            client_base,
            filesystem_base,
            count,
        }
    }

    /// Translate an incoming client ID into the filesystem's namespace.
    #[inline]
    pub fn to_filesystem(self, id: u32) -> u32 {
        match id.checked_sub(self.client_base) {
            Some(offset) if offset < self.count => self.filesystem_base + offset,
            _ => id,
        }
    }

    /// Translate an outgoing filesystem ID into the client's namespace.
    #[inline]
    pub fn to_client(self, id: u32) -> u32 {
        match id.checked_sub(self.filesystem_base) {
            Some(offset) if offset < self.count => self.client_base + offset,
            _ => id,
        }
    }
}

/// Translation at the boundary between a client and a [`crate::Filesystem`].
///
/// This maps request credentials, SETATTR ownership arguments, and ownership
/// in attribute replies. It does not interpret IDs in opaque data such as
/// extended attributes. Session ACL checks use the original client credentials.
/// The default mapping is identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilesystemMapping {
    /// User ID translation.
    pub uid: IdMap,
    /// Group ID translation, independent of user ID translation.
    pub gid: IdMap,
}

#[cfg(test)]
mod tests {
    use super::IdMap;

    #[test]
    fn range_boundaries_and_identity_fallback() {
        let map = IdMap::new(10, 100, 3);
        for (client, filesystem) in [(9, 9), (10, 100), (12, 102), (13, 13), (u32::MAX, u32::MAX)] {
            assert_eq!(map.to_filesystem(client), filesystem);
        }
        for (filesystem, client) in [
            (99, 99),
            (100, 10),
            (102, 12),
            (103, 103),
            (u32::MAX, u32::MAX),
        ] {
            assert_eq!(map.to_client(filesystem), client);
        }
        for id in [0, 1, 10, 100, u32::MAX] {
            assert_eq!(IdMap::default().to_filesystem(id), id);
            assert_eq!(IdMap::default().to_client(id), id);
        }
    }

    #[test]
    fn large_range() {
        let map = IdMap::new(1, 100_000, u32::MAX - 100_000);
        for (client, filesystem) in [
            (0, 0),
            (1, 100_000),
            (1000, 100_999),
            (u32::MAX - 100_000, u32::MAX - 1),
        ] {
            assert_eq!(map.to_filesystem(client), filesystem);
            assert_eq!(map.to_client(filesystem), client);
        }
        assert_eq!(map.to_filesystem(u32::MAX - 99_999), u32::MAX - 99_999);
        assert_eq!(map.to_client(99_999), 99_999);
        assert_eq!(map.to_client(u32::MAX), u32::MAX);
    }

    #[test]
    #[should_panic]
    fn rejects_client_range_overflow() {
        IdMap::new(u32::MAX, 0, 1);
    }

    #[test]
    #[should_panic]
    fn rejects_filesystem_range_overflow() {
        IdMap::new(0, u32::MAX, 1);
    }
}
