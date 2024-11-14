use crate::nostr_group_data_extension::NostrGroupDataExtension;
use crate::NostrMls;
use openmls::prelude::*;
use tls_codec::Deserialize as TlsDeserialize;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq, Clone)]
pub enum WelcomeError {
    #[error("Error creating the welcome: {0}")]
    CreateWelcomeError(String),

    #[error("Error parsing the welcome: {0}")]
    ParseWelcomeError(String),

    #[error("Error processing the welcome: {0}")]
    ProcessWelcomeError(String),

    #[error("Error joining the group: {0}")]
    JoinGroupError(String),

    #[error("Error deserializing the welcome: {0}")]
    DeserializeWelcomeError(String),
}

#[derive(Debug)]
pub struct WelcomePreview {
    pub staged_welcome: StagedWelcome,
    pub nostr_group_data: NostrGroupDataExtension,
}

#[derive(Debug)]
pub struct JoinedGroupResult {
    pub mls_group: MlsGroup,
    pub nostr_group_data: NostrGroupDataExtension,
}

pub fn parse_welcome_message(
    nostr_mls: &NostrMls,
    welcome_message: Vec<u8>,
) -> Result<(StagedWelcome, NostrGroupDataExtension), WelcomeError> {
    let welcome_message_in = MlsMessageIn::tls_deserialize(&mut welcome_message.as_slice())
        .map_err(|e| WelcomeError::DeserializeWelcomeError(e.to_string()))?;
    let welcome = match welcome_message_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => {
            return Err(WelcomeError::ParseWelcomeError(
                "Invalid welcome message".to_string(),
            ))
        }
    };

    let mls_group_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let staged_welcome =
        StagedWelcome::new_from_welcome(&nostr_mls.provider, &mls_group_config, welcome, None)
            .map_err(|e| WelcomeError::ProcessWelcomeError(e.to_string()))?;

    let nostr_group_data =
        NostrGroupDataExtension::from_group_context(staged_welcome.group_context())
            .map_err(|e| WelcomeError::ProcessWelcomeError(e.to_string()))?;

    Ok((staged_welcome, nostr_group_data))
}

pub fn preview_welcome_event(
    nostr_mls: &NostrMls,
    welcome_message: Vec<u8>,
) -> Result<WelcomePreview, WelcomeError> {
    let (staged_welcome, nostr_group_data) = parse_welcome_message(nostr_mls, welcome_message)?;

    Ok(WelcomePreview {
        staged_welcome,
        nostr_group_data,
    })
}

pub fn join_group_from_welcome(
    nostr_mls: &NostrMls,
    welcome_message: Vec<u8>,
) -> Result<JoinedGroupResult, WelcomeError> {
    let (staged_welcome, nostr_group_data) = parse_welcome_message(nostr_mls, welcome_message)?;

    let mls_group = staged_welcome
        .into_group(&nostr_mls.provider)
        .map_err(|e| WelcomeError::JoinGroupError(format!("Error joining group: {:?}", e)))?;

    Ok(JoinedGroupResult {
        mls_group,
        nostr_group_data,
    })
}
