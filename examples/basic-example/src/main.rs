use std::path::PathBuf;
use nostr_sdk::*;
use nostr_openmls::*;
use std::error::Error;
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use openmls::group::{MlsGroup, GroupId};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    test_self_update().await?;
    Ok(())
}

/// Test self update functionality
async fn test_self_update() -> Result<(), Box<dyn Error>> {
    tracing::info!("Starting self update test");
    
    // Initialize NostrMLS instances
    let alice_mls = NostrMls::new(PathBuf::from("./nostr-mls-alice"), None);
    let bob_mls = NostrMls::new(PathBuf::from("./nostr-mls-bob"), None);

    // Generate nostr keys
    let alice_keys = Keys::generate();
    let bob_keys = Keys::generate();
    
    tracing::info!("Created keys for Alice and Bob");

    // Create Bob's key package
    let bob_encoded_key_package = nostr_openmls::key_packages::create_key_package_for_event(
        bob_keys.public_key().to_hex(), 
        &bob_mls
    )?;
    let bob_key_package = nostr_openmls::key_packages::parse_key_package(
        bob_encoded_key_package, 
        &alice_mls
    )?;

    // Alice creates the group
    let group_create_result = alice_mls.create_group(
        "Test Group".to_string(), 
        "Testing self update".to_string(), 
        vec![bob_key_package], 
        vec![alice_keys.public_key().to_hex()], 
        alice_keys.public_key().to_hex(),
        vec!["ws://localhost:8080".to_string()]
    )?;

    let alice_group_id = group_create_result.mls_group.group_id().to_vec();
    tracing::info!("Alice created the group");

    // Bob joins the group
    let bob_join_result = bob_mls.join_group_from_welcome(group_create_result.serialized_welcome_message)?;
    let bob_group_id = bob_join_result.mls_group.group_id().to_vec();
    tracing::info!("Bob joined the group");

    // Verify initial state
    verify_group_state(
        &alice_mls,
        &alice_group_id,
        &[alice_keys.public_key().to_hex(), bob_keys.public_key().to_hex()],
        ""
    ).await?;
    verify_group_state(
        &bob_mls,
        &bob_group_id,
        &[alice_keys.public_key().to_hex(), bob_keys.public_key().to_hex()],
        ""
    ).await?;
    tracing::info!("Initial group state verified");

    // add test messsage
    tracing::info!(target: "basic_example", "Testing message sending and receiving...");
    
    // Alice creates and sends a test message
    let test_message = "Hello from Alice!".to_string();
    let encrypted_message = bob_mls.create_message_for_group(bob_group_id.clone(), test_message.clone())
        .expect("Failed to create message");
    tracing::info!(target: "basic_example", "Alice created message: {}", test_message);

    // Bob processes Alice's message
    let decrypted_message = alice_mls.process_message_for_group(alice_group_id.clone(), encrypted_message)
        .expect("Failed to process message");
    let received_message = String::from_utf8(decrypted_message)
        .expect("Failed to convert decrypted message to string");
    tracing::info!(target: "basic_example", "Bob received message: {}", received_message);

    // Verify the message content
    assert_eq!(test_message, received_message, "Message content mismatch");
    tracing::info!(target: "basic_example", "Message test completed successfully!");

    // Test Bob's self update
    let update_result = bob_mls.self_update(bob_group_id.clone())?;
    tracing::info!("Bob performed self update");

    // Alice processes Bob's update message
    alice_mls.process_message_for_group(alice_group_id.clone(), update_result.serialized_message)?;
    tracing::info!("Alice processed Bob's self update message");


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

    // Verify final state
    verify_group_state(
        &alice_mls,
        &alice_group_id,
        &[alice_keys.public_key().to_hex(), bob_keys.public_key().to_hex()],
        ""
    ).await?;
    verify_group_state(
        &bob_mls,
        &bob_group_id,
        &[alice_keys.public_key().to_hex(), bob_keys.public_key().to_hex()],
        ""
    ).await?;
    tracing::info!("Final group state verified");

    tracing::info!("Self update test completed successfully");
    Ok(())
}

/// Helper function to verify group state
async fn verify_group_state(
    nostr_mls: &NostrMls,
    group_id: &[u8],
    expected_members: &[String],
    _group_name: &str,
) -> Result<(), Box<dyn Error>> {
    let member_pubkeys = nostr_mls.member_pubkeys(group_id.to_vec())?;
    
    assert_eq!(
        member_pubkeys.len(),
        expected_members.len(),
        "Unexpected number of members in group"
    );
    
    for expected_member in expected_members {
        assert!(
            member_pubkeys.contains(expected_member),
            "Expected member {} not found in group",
            expected_member
        );
    }
    
    Ok(())
}
