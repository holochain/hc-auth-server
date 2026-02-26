use base64::prelude::*;
use ed25519_dalek::SigningKey;
use rand::prelude::*;
use serde_json::json;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

/// Example client that demonstrates the full authentication flow.
///
/// 1. Generates an Ed25519 keypair.
/// 2. Requests authentication from the server.
/// 3. Uses an API token to list and approve the request (for demonstration).
/// 4. Signs a challenge from the server to obtain an authentication token.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 0. Parse API token from command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <api-token>", args[0]);
        std::process::exit(1);
    }
    let api_token = &args[1];

    // 1. Generate a new ed25519 keypair
    let mut seed = [0; 32];
    rand::rng().fill(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // 2. Prepare the public key (base64url encoded)
    let pubkey_bytes = verifying_key.to_bytes();
    let pubkey_b64 = BASE64_URL_SAFE_NO_PAD.encode(pubkey_bytes);

    println!("Generated Keypair:");
    println!("  Public Key (Base64URL): {}", pubkey_b64);

    // 3. Request Authentication
    let client = reqwest::Client::new();
    let base_url = "http://127.0.0.1:3000"; // Assuming default port
    let request_url = format!("{}/request-auth/{}", base_url, pubkey_b64);

    println!("\nStep 1: Requesting authentication...");
    println!("  PUT {}", request_url);

    let payload = json!({
        "agent": "rust-automated-client",
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    });

    let resp = client.put(&request_url).json(&payload).send().await?;

    if !resp.status().is_success() {
        eprintln!("Failed to request auth: {}", resp.status());
        let text = resp.text().await?;
        eprintln!("Response: {}", text);
        return Ok(());
    }
    println!("  Success!");

    // 3.1 Verify 202 response for pending key
    println!("\nStep 1.1: Verifying 202 ACCEPTED for pending key...");
    let pending_auth_resp =
        perform_auth(&client, base_url, &signing_key, &pubkey_b64).await?;
    if pending_auth_resp.status() == reqwest::StatusCode::ACCEPTED {
        println!("  Success! Received 202 ACCEPTED for pending key.");
    } else {
        eprintln!(
            "  Error: Expected 202 ACCEPTED, got {}",
            pending_auth_resp.status()
        );
        return Ok(());
    }

    // 4. Automated Management (using API Token)
    println!("\nStep 2: Automated Management (using API token)");
    let auth_header = format!("Bearer {}", api_token);

    // 4.1. List all requests
    println!("  Listing all requests...");
    let list_resp = client
        .get(format!("{}/api/list", base_url))
        .header("Authorization", &auth_header)
        .send()
        .await?;

    if !list_resp.status().is_success() {
        eprintln!("Failed to list: {}", list_resp.status());
        return Ok(());
    }
    let requests: Vec<serde_json::Value> = list_resp.json().await?;
    let found = requests.iter().any(|r| {
        r.get("pubKey").and_then(|v| v.as_str()) == Some(&pubkey_b64)
    });
    if !found {
        eprintln!(
            "Error: Newly created key {} not found in list!",
            pubkey_b64
        );
        return Ok(());
    }
    println!("  Confirm: Key is in the list.");

    // 4.2. Verify it's pending
    println!("  Verifying state is pending...");
    let get_resp = client
        .get(format!("{}/api/get/{}", base_url, pubkey_b64))
        .header("Authorization", &auth_header)
        .send()
        .await?;
    let data: serde_json::Value = get_resp.json().await?;
    if data.get("state").and_then(|v| v.as_str()) != Some("pending") {
        eprintln!("Error: Expected state 'pending', got {:?}", data.get("state"));
        return Ok(());
    }
    println!("  Success: State is pending.");

    // 4.3. Transition to blocked
    println!("  Transitioning to blocked...");
    let transition_resp = client
        .post(format!("{}/api/transition", base_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "pubKey": pubkey_b64,
            "oldState": "pending",
            "newState": "blocked"
        }))
        .send()
        .await?;

    if !transition_resp.status().is_success() {
        eprintln!("Failed to block: {}", transition_resp.status());
        return Ok(());
    }
    println!("  Success: Transitioned to blocked.");

    // 4.4. Verify it's blocked
    println!("  Verifying state is blocked...");
    let get_resp = client
        .get(format!("{}/api/get/{}", base_url, pubkey_b64))
        .header("Authorization", &auth_header)
        .send()
        .await?;
    let data: serde_json::Value = get_resp.json().await?;
    if data.get("state").and_then(|v| v.as_str()) != Some("blocked") {
        eprintln!("Error: Expected state 'blocked', got {:?}", data.get("state"));
        return Ok(());
    }
    println!("  Success: State is blocked.");

    // 4.5. Transition to authorized
    println!("  Transitioning to authorized...");
    let transition_resp = client
        .post(format!("{}/api/transition", base_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "pubKey": pubkey_b64,
            "oldState": "blocked",
            "newState": "authorized"
        }))
        .send()
        .await?;

    if !transition_resp.status().is_success() {
        eprintln!("Failed to authorize: {}", transition_resp.status());
        return Ok(());
    }
    println!("  Success: Transitioned to authorized.");

    // 5. Verify Authentication
    println!("\nStep 3: Verifying final authentication...");

    let resp = perform_auth(&client, base_url, &signing_key, &pubkey_b64).await?;

    if resp.status().is_success() {
        println!("  Authentication Successful!");
        let resp_json: serde_json::Value = resp.json().await?;
        if let Some(token) = resp_json.get("authToken").and_then(|t| t.as_str())
        {
            println!("\nFinal Auth Token:");
            println!("{}", token);
        }
    } else {
        println!("  Authentication FAILED: {}", resp.status());
        let text = resp.text().await?;
        println!("  Response: {}", text);
    }

    Ok(())
}

/// Helper function to perform the authentication handshake.
async fn perform_auth(
    client: &reqwest::Client,
    base_url: &str,
    signing_key: &ed25519_dalek::SigningKey,
    pubkey_b64: &str,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    // Get fresh payload from /now
    let now_url = format!("{}/now", base_url);
    let now_resp = client.get(&now_url).send().await?.error_for_status()?;
    let payload_b64 = now_resp.text().await?;
    let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(&payload_b64)?;

    // Sign the payload
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(&payload_bytes);
    let signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let auth_body = json!({
        "pubKey": pubkey_b64,
        "payload": payload_b64,
        "signature": signature_b64,
    });

    // Authenticate
    let auth_url = format!("{}/authenticate", base_url);
    let resp = client
        .put(&auth_url)
        .header("Content-Type", "application/octet-stream")
        .body(auth_body.to_string())
        .send()
        .await?;

    Ok(resp)
}
