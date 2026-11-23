//! Standalone Merkle CCEC Inclusion Proof Verifier (`cargo run --example verify_merkle -- <merkle.json>`).

use nosih_caznsos::plane1::merkle::proof::verify_inclusion_hex;
use serde_json::Value;
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: verify_merkle <exported_merkle.json>");
        process::exit(1);
    }
    let raw = fs::read_to_string(&args[1]).unwrap_or_else(|e| {
        eprintln!("Failed to read '{}': {e}", args[1]);
        process::exit(1);
    });
    let doc: Value = serde_json::from_str(&raw).unwrap_or_else(|e| {
        eprintln!("Invalid JSON: {e}");
        process::exit(1);
    });
    let root = doc["root_hash_hex"].as_str().unwrap_or("");
    let tree_size = doc["tree_size"].as_u64().unwrap_or(0) as usize;
    let leaf_index = doc["leaf_index"].as_u64().unwrap_or(0) as usize;
    let payload = doc["payload_jcs"].as_str().unwrap_or("");
    let proof: Vec<String> = doc["inclusion_proof"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let ok = verify_inclusion_hex(payload.as_bytes(), leaf_index, tree_size, &proof, root);
    println!("Merkle Tree Size: {tree_size}");
    println!("Leaf Index:       {leaf_index}");
    println!("Root Hash:        {root}");
    println!("Verified:         {ok}");
    if !ok {
        process::exit(2);
    }
}
