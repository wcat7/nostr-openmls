use std::path::PathBuf;
use nostr_sdk::*;
use nostr_openmls::*;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    // Initialize NostrMLS
    let nostr_mls = NostrMls::new(PathBuf::from("./nostr-mls"), None);

    // Generate nostr keys
    let alice_keys = Keys::generate();
    let bob_keys = Keys::generate();

    // Create key package for Bob
    // The encoded key package is the one that will be published in a 443 event to the Nostr network
    let bob_encoded_key_package = nostr_openmls::key_packages::create_key_package_for_event(
        bob_keys.public_key().to_hex(), 
        &nostr_mls
    )?;

    // ================================
    // We're now acting as Alice
    // ================================

    // To create a group, Alice fetches Bob's key package from the Nostr network and parses it
    let bob_key_package = nostr_openmls::key_packages::parse_key_package(
        bob_encoded_key_package, 
        &nostr_mls
    )?;

    // Alice creates the group, adding Bob.
    let group_create_result = nostr_mls.create_group(
        "Bob & Alice".to_string(), 
        "A secret chat between Bob and Alice".to_string(), 
        vec![bob_key_package], 
        vec![alice_keys.public_key().to_hex(), bob_keys.public_key().to_hex()], 
        alice_keys.public_key().to_hex(), 
        vec!["ws://localhost:8080".to_string()]
    )?;


    // The group is created, and the welcome message is serialized to send to Bob.
    // We also have the Nostr group data, which we can use to show info about the group.
    let alice_mls_group = group_create_result.mls_group;
    let serialized_welcome_message = group_create_result.serialized_welcome_message;
    let alice_group_data = group_create_result.nostr_group_data;

    assert_eq!(alice_mls_group.members().count(), 2, "Groups should have 2 members");
    assert_eq!(
        String::from_utf8(alice_group_data.name).unwrap(), 
        "Bob & Alice", 
        "Group name should be Bob & Alice"
    );
    assert_eq!(
        String::from_utf8(alice_group_data.description.clone()).unwrap(), 
        "A secret chat between Bob and Alice", 
        "Group description should be A secret chat between Bob and Alice"
    );
    assert_eq!(
        alice_group_data.admin_pubkeys.iter().map(|p| String::from_utf8(p.clone()).unwrap()).collect::<Vec<String>>(),
        vec![alice_keys.public_key().to_hex(), bob_keys.public_key().to_hex()],
        "Group admin pubkeys should be Alice and Bob"
    );
    assert_eq!(
        alice_group_data.relays.iter().map(|r| String::from_utf8(r.clone()).unwrap()).collect::<Vec<String>>(),
        vec!["ws://localhost:8080".to_string()],
        "Group relays should be ws://localhost:8080"
    );

    // At this point, Alice would publish a Kind: 444 event that is Gift-wrapped to just 
    // Bob with the welcome event in the rumor event.

    // Now, let's also try sending a message to the group (using an unsigned Kind: 9 event)
    // We don't have to wait for Bob to join the group before we send our first message.
    let message_event = EventBuilder::new(
        Kind::Custom(9), 
        "Hi Bob!"
    ).tags(vec![]).build(alice_keys.public_key());

    // This is the serialized message object that will be encrypted into a Kind: 445 event and published.
    let serialized_message = nostr_mls.create_message_for_group(
        alice_mls_group.group_id().to_vec(), 
        serde_json::json!(message_event).to_string()
    )?;

    // Get the export secret value for this epoch of the group
    // In real usage you would want to do this once per epoch, per group, and cache it.
    // 🚨 It's critical that you delete this secret after some period of time to preserve forward secrecy.
    // For example, once the group has moved 2 epochs beyond this one.
    let (export_secret_hex, _epoch) = nostr_mls
        .export_secret_as_hex_secret_key_and_epoch(alice_mls_group.group_id().to_vec())?;
    
    // Convert that secret to nostr keys
    let export_nostr_keys = Keys::parse(&export_secret_hex)?;

    // Encrypt the message content
    let encrypted_content = nostr_sdk::nips::nip44::encrypt(
        export_nostr_keys.secret_key(),
        &export_nostr_keys.public_key(),
        &serialized_message,
        nostr_sdk::nips::nip44::Version::V2,
    )?;

    // Now we'll create a Kind: 445 event with the encrypted message content
    let ephemeral_nostr_keys = Keys::generate();

    let alice_message_event = EventBuilder::new(Kind::MlsGroupMessage, encrypted_content)
        .tags(vec![
            Tag::custom(TagKind::h(), vec![hex::encode(alice_group_data.nostr_group_id)])
        ])
        .sign(&ephemeral_nostr_keys)
        .await?;

    // ================================
    // We're now acting as Bob
    // ================================

    // First Bob recieves the Gift-wrapped welcome message from Alice and decrypts it.
    // Bob can now preview the welcome message to see what group he might be joining
    let welcome_preview = nostr_mls.preview_welcome_event(serialized_welcome_message.clone()).expect("Error previewing welcome event");
    assert_eq!(welcome_preview.staged_welcome.members().count(), alice_mls_group.members().count(), "Welcome message group member count should match the group member count");
    assert_eq!(String::from_utf8(welcome_preview.nostr_group_data.name).unwrap(), "Bob & Alice", "Welcome message group name should be Bob & Alice");

    // Bob can now join the group
    let join_result = nostr_mls.join_group_from_welcome(serialized_welcome_message.clone())?;
    let bob_mls_group = join_result.mls_group;
    let bob_group_data = join_result.nostr_group_data;

    // Bob and Alice now have synced state for the group.
    assert_eq!(bob_mls_group.members().count(), alice_mls_group.members().count(), "Groups should have 2 members");
    assert_eq!(
        String::from_utf8(bob_group_data.name).unwrap(), 
        "Bob & Alice", 
        "Group name should be Bob & Alice"
    );

    // Bob fetches the message event (Kind: 445) from Nostr and, using
    // the exporter secret key, decrypts the message content to bytes
    let serialized_message = nostr_sdk::nips::nip44::decrypt_to_bytes(
        export_nostr_keys.secret_key(),
        &export_nostr_keys.public_key(),
        &alice_message_event.content
    )?;

    // The resulting serialized message is the MLS encrypted message that Bob sent
    // Now Bob can process the MLS message content and do what's needed with it
    let processed_message = nostr_mls.process_message_for_group(bob_mls_group.group_id().to_vec(), serialized_message)?;
    let json_value = serde_json::from_slice::<serde_json::Value>(&processed_message)?;
    let json_str = json_value.to_string();

    // This is the interior message event that was decrypted from the MLS message
    // This is the Nostr event that is added to the group transcript.
    let json_event = UnsignedEvent::from_json(&json_str).unwrap();

    assert_eq!(json_event.kind, Kind::Custom(9), "Message event kind should be Custom(9)");
    assert_eq!(json_event.pubkey, alice_keys.public_key(), "Message event pubkey should be Alice's pubkey");
    assert_eq!(json_event.content, "Hi Bob!", "Message event content should be Hi Bob!");

    tracing::info!("Interior message event: {:#?}", json_event);

    Ok(())
}
