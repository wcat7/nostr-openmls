//! OpenMLS Nostr is a library that simplifies the implmentation of NIP-104 Nostr Groups using the OpenMLS implementation of the MLS protocol.
//! It's expected that you'd use this library along with the [Rust Nostr library](https://github.com/rust-nostr/nostr).

use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use openmls_sled_storage::{SledStorage, SledStorageError};
use std::path::PathBuf;

pub mod key_packages;
pub mod nostr_credential;
pub mod nostr_group_data_extension;

#[cfg(test)]
pub mod test_utils;

/// The main struct for the Nostr MLS implementation.
pub struct NostrMls {
    // The ciphersuite to use
    ciphersuite: Ciphersuite,
    // The required extensions
    extensions: Vec<ExtensionType>,
    // An implementation of the OpenMls provider trait
    provider: NostrMlsProvider,
}

/// The provider struct for Nostr MLS that implements the OpenMLS Provider trait.
pub struct NostrMlsProvider {
    crypto: RustCrypto,
    key_store: SledStorage,
}

impl OpenMlsProvider for NostrMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SledStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl NostrMls {
    /// Default ciphersuite for Nostr Groups.
    /// This is also the only required ciphersuite for Nostr Groups.
    const DEFAULT_CIPHERSUITE: Ciphersuite =
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    /// Required extensions for Nostr Groups.
    const REQUIRED_EXTENSIONS: &[ExtensionType] = &[
        ExtensionType::RequiredCapabilities,
        ExtensionType::LastResort,
        ExtensionType::RatchetTree,
        ExtensionType::Unknown(0xF233), // Nostr Group Data Extension
    ];

    /// GREASE values for MLS.
    #[allow(dead_code)] // TODO: Remove this once we've added GREASE support.
    const GREASE: &[u16] = &[
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
        0xBABA, 0xCACA, 0xDADA, 0xEAEA,
    ];

    pub fn new(storage_path: PathBuf, current_identity: Option<String>) -> Self {
        // TODO: This is a bit messy and could be improved.
        // We want MLS data to be stored on a per user basis so we create a new path
        // and hence a new database instance for each user.
        // However, if we don't have a current identity (which means we're not going to use MLS)
        // we can just use the default path (which creates an empty database).
        let key_store = match current_identity.as_ref() {
            Some(identity) => SledStorage::new_from_path(format!(
                "{}/{}/{}",
                storage_path.to_string_lossy(),
                "mls_storage",
                identity
            )),
            None => SledStorage::new_from_path(format!(
                "{}/{}",
                storage_path.to_string_lossy(),
                "mls_storage"
            )),
        }
        .expect("Failed to create MLS storage with the right path");

        let provider = NostrMlsProvider {
            key_store,
            crypto: RustCrypto::default(),
        };

        Self {
            ciphersuite: Self::DEFAULT_CIPHERSUITE,
            extensions: Self::REQUIRED_EXTENSIONS.to_vec(),
            provider,
        }
    }

    /// Updates the provider for a given user identity.
    ///
    /// This method updates the current identity and key store of the provider
    /// based on the given user identity.
    ///
    /// # Arguments
    ///
    /// * `current_identity` - An `Option<String>` representing the current user's identity.
    ///   If `None`, it indicates no active user.
    ///
    // pub fn update_provider_for_user(&self, current_identity: Option<String>) {
    //     // First, flush (and block) until all pending writes are persisted to disk.
    //     self.provider.key_store.flush().map_err(|e| NostrMls)
    //         .key_store
    //         .flush()
    //         .expect("Failed to flush provider storage data");

    //     provider.current_identity = current_identity.clone();

    //     let key_store = match current_identity.clone() {
    //         Some(identity) => SledStorage::new_from_path(format!(
    //             "{}/{}/{}",
    //             self.storage_path.to_string_lossy(),
    //             "mls_storage",
    //             identity
    //         )),
    //         None => SledStorage::new_from_path(format!(
    //             "{}/{}",
    //             self.storage_path.to_string_lossy(),
    //             "mls_storage"
    //         )),
    //     }
    //     .expect("Failed to create MLS storage with the right path");

    //     provider.key_store = key_store;

    //     tracing::debug!(
    //         target: "nostr_mls::update_provider_for_user",
    //         "Updated provider for user: {:?}",
    //         current_identity.clone()
    //     );
    // }

    pub fn delete_data(&self) -> Result<(), SledStorageError> {
        tracing::debug!(target: "nostr_mls::delete_data", "Deleting all data from key store");
        self.provider.key_store.delete_all_data()
    }

    pub fn ciphersuite_value(&self) -> u16 {
        self.ciphersuite.into()
    }

    pub fn extensions_value(&self) -> String {
        self.extensions
            .iter()
            .map(|e| format!("{:?}", e))
            .collect::<Vec<String>>()
            .join(",")
    }
}
