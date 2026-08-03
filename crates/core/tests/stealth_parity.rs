//! Golden-vector parity for the Domain-A stealth core vs the REAL Go WASM
//! (curvy-core). Validates the dual-curve scheme end-to-end — including the
//! gnark-GT-tower → secp256k1 `b`-coercion and the BN254/secp256k1 generators.

use curvy_core::stealth::{get_meta, scan, send_with_r};
use serde::Deserialize;

#[derive(Deserialize)]
struct Keys {
    k: String,
    v: String,
    #[serde(rename = "K")]
    big_k: String,
    #[serde(rename = "V")]
    big_v: String,
}

#[derive(Deserialize)]
struct Send {
    #[serde(rename = "K")]
    big_k: String,
    #[serde(rename = "V")]
    big_v: String,
    r: String,
    #[serde(rename = "R")]
    big_r: String,
    #[serde(rename = "viewTag")]
    view_tag: String,
    #[serde(rename = "spendingPubKey")]
    spending_pub_key: String,
}

#[derive(Deserialize)]
struct Scan {
    k: String,
    v: String,
    #[serde(rename = "Rs")]
    rs: Vec<String>,
    #[serde(rename = "viewTags")]
    view_tags: Vec<String>,
    #[serde(rename = "spendingPubKeys")]
    spending_pub_keys: Vec<String>,
    #[serde(rename = "spendingPrivKeys")]
    spending_priv_keys: Vec<String>,
}

#[derive(Deserialize)]
struct Vectors {
    keys: Vec<Keys>,
    send: Vec<Send>,
    scan: Vec<Scan>,
}

const JSON: &str = include_str!("../testdata/stealth_vectors.json");

#[test]
fn get_meta_matches_go() {
    let v: Vectors = serde_json::from_str(JSON).unwrap();
    assert!(!v.keys.is_empty());
    for (i, key) in v.keys.iter().enumerate() {
        let (k, big_v) = get_meta(&key.k, &key.v).expect("golden-vector keys are valid");
        assert_eq!(k, key.big_k, "get_meta K (keyset {i})");
        assert_eq!(big_v, key.big_v, "get_meta V (keyset {i})");
    }
}

#[test]
fn send_matches_go() {
    let v: Vectors = serde_json::from_str(JSON).unwrap();
    assert!(!v.send.is_empty());
    for (i, s) in v.send.iter().enumerate() {
        let out =
            send_with_r(&s.r, &s.big_k, &s.big_v).expect("golden-vector send inputs are valid");
        assert_eq!(out.big_r, s.big_r, "send R ({i})");
        assert_eq!(out.view_tag, s.view_tag, "send viewTag ({i})");
        assert_eq!(
            out.spending_pub_key, s.spending_pub_key,
            "send spendingPubKey ({i}) — b-coercion"
        );
    }
}

#[test]
fn scan_matches_go() {
    let v: Vectors = serde_json::from_str(JSON).unwrap();
    assert!(!v.scan.is_empty());
    for (i, sc) in v.scan.iter().enumerate() {
        let out =
            scan(&sc.k, &sc.v, &sc.rs, &sc.view_tags).expect("golden-vector scan inputs are valid");
        // The fixtures record the Go core's DENSE arrays ("" at non-matches);
        // scan is now sparse — rebuild dense from (index, keys) and compare.
        let mut dense_pubs = vec![String::new(); sc.rs.len()];
        let mut dense_privs = vec![String::new(); sc.rs.len()];
        for m in out {
            dense_pubs[m.index as usize] = m.spending_pub_key;
            dense_privs[m.index as usize] = m.spending_priv_key;
        }
        assert_eq!(
            dense_pubs, sc.spending_pub_keys,
            "scan spendingPubKeys ({i})"
        );
        assert_eq!(
            dense_privs, sc.spending_priv_keys,
            "scan spendingPrivKeys ({i})"
        );
    }
}
