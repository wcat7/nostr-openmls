use crate::NostrMls;
use crate::{
    key_packages::generate_credential_with_key, nostr_group_data_extension::NostrGroupDataExtension,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::Serialize as TlsSerialize;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq, Clone)]
pub enum GroupError {
    #[error("Error creating the group: {0}")]
    CreateGroupError(String),

    #[error("Error loading MLS group from storage: {0}")]
    LoadGroupError(String),

    #[error("Error creating message for group: {0}")]
    CreateMessageError(String),

    #[error("Error serializing message for group: {0}")]
    SerializeMessageError(String),
}

#[derive(Debug)]
pub struct CreateGroupResult {
    pub mls_group: MlsGroup,
    pub serialized_welcome_message: Vec<u8>,
    pub nostr_group_data: NostrGroupDataExtension,
}

pub fn create_mls_group(
    nostr_mls: &NostrMls,
    name: String,
    description: String,
    member_key_packages: Vec<KeyPackage>,
    admin_pubkeys_hex: Vec<String>,
    creator_pubkey_hex: String,
    group_relays: Vec<String>,
) -> Result<CreateGroupResult, GroupError> {
    let capabilities = nostr_mls.default_capabilities();

    let (credential, signer) = generate_credential_with_key(creator_pubkey_hex.clone(), nostr_mls)
        .map_err(|e| GroupError::CreateGroupError(e.to_string()))?;

    tracing::debug!(
        target: "nostr_mls::groups::create_mls_group",
        "Credential and signer created, {:?}",
        credential
    );

    let group_data =
        NostrGroupDataExtension::new(name, description, admin_pubkeys_hex, group_relays);

    tracing::debug!(
        target: "nostr_mls::groups::create_mls_group",
        "Group data created, {:?}",
        group_data
    );

    let serialized_group_data = group_data
        .tls_serialize_detached()
        .expect("Failed to serialize group data");

    let extensions = vec![Extension::Unknown(
        group_data.extension_type(),
        UnknownExtension(serialized_group_data),
    )];

    tracing::debug!(
        target: "nostr_mls::groups::create_mls_group",
        "Group config extensions created, {:?}",
        extensions
    );

    // Build the group config
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(nostr_mls.ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities)
        .with_group_context_extensions(
            Extensions::from_vec(extensions).expect("Couldn't convert extensions vec to Object"),
        )
        .map_err(|e| GroupError::CreateGroupError(e.to_string()))?
        .build();

    tracing::debug!(
        target: "nostr_mls::groups::create_mls_group",
        "Group config built, {:?}",
        group_config
    );

    let mut group = MlsGroup::new(
        &nostr_mls.provider,
        &signer,
        &group_config,
        credential.clone(),
    )
    .map_err(|e| GroupError::CreateGroupError(e.to_string()))?;

    // Add members to the group
    let (_, welcome_out, _group_info) = group
        .add_members(&nostr_mls.provider, &signer, member_key_packages.as_slice())
        .map_err(|e| GroupError::CreateGroupError(e.to_string()))?;

    // Merge the pending commit adding the memebers
    group
        .merge_pending_commit(&nostr_mls.provider)
        .map_err(|e| GroupError::CreateGroupError(e.to_string()))?;

    // Serialize the welcome message and send it to the members
    let serialized_welcome_message = welcome_out
        .tls_serialize_detached()
        .map_err(|e| GroupError::CreateGroupError(e.to_string()))?;

    Ok(CreateGroupResult {
        mls_group: group,
        serialized_welcome_message,
        nostr_group_data: group_data,
    })
}

pub fn create_message_for_group(
    nostr_mls: &NostrMls,
    mls_group_id: Vec<u8>,
    message: String,
) -> Result<Vec<u8>, GroupError> {
    let mut group = MlsGroup::load(
        nostr_mls.provider.storage(),
        &GroupId::from_slice(&mls_group_id),
    )
    .map_err(|e| GroupError::LoadGroupError(e.to_string()))?
    .ok_or_else(|| GroupError::LoadGroupError("Group not found".to_string()))?;

    let signer = SignatureKeyPair::read(
        nostr_mls.provider.storage(),
        group.own_leaf().unwrap().signature_key().clone().as_slice(),
        group.ciphersuite().signature_algorithm(),
    )
    .ok_or_else(|| GroupError::LoadGroupError("Failed to load signer".to_string()))?;

    let message_out = group
        .create_message(&nostr_mls.provider, &signer, message.as_bytes())
        .map_err(|e| GroupError::CreateMessageError(e.to_string()))?;

    let serialized_message = message_out
        .tls_serialize_detached()
        .map_err(|e| GroupError::SerializeMessageError(e.to_string()))?;

    Ok(serialized_message)
}
// Send a message to a group

// Fetch and process messages from a group

// Get group member public keys

// Export secret as keys
