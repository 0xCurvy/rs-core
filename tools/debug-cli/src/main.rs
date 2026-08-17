//! Interactive REPL for Curvy core workflows.
//!
//! Covers stealth, crypto primitives, notes trees, witness builders, and the
//! committed Groth16 demo fixture.
//!
//! ```text
//! cargo run -p curvy-debug-cli
//! cargo run -p curvy-debug-cli -- stealth demo
//! echo 'prove demo' | cargo run -p curvy-debug-cli
//! ```
//!
//! Blank lines and `#` comments are ignored in piped scripts. Use `rlwrap` for
//! line editing and history.

use std::env;
use std::io::{self, BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Instant;

use curvy_core::NOTES_TREE_DEPTH;
use curvy_core::babyjubjub;
use curvy_core::cipher::{decrypt_amount_token, encrypt_amount_token};
use curvy_core::eddsa::{self, ScalarSigningKey, verify_scalar_compat};
use curvy_core::encoding::from_hex_exact;
use curvy_core::field::{Bn254Fr, Fr, fr_from_dec, fr_to_dec};
use curvy_core::hash_utils::sha256_bigint;
use curvy_core::imt::Imt;
use curvy_core::note;
use curvy_core::poseidon;
use curvy_core::stealth;
use curvy_core::witness::{self, Note, NoteSigner, Proof, SeedNoteSigner};
use curvy_prover::CircuitProver;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// Deterministic witness-demo seed containing bytes `0x00..=0x1f`.
const DEMO_OWNER_SEED_HEX: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
/// Deterministic fee-note seed containing bytes `0x20..=0x3f`.
const DEMO_FEE_SEED_HEX: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

/// Committed prover fixture shared with the prover tests.
const MULTIPLIER_ZKEY: &[u8] = include_bytes!("../../../crates/prover/testdata/multiplier.zkey");
const MULTIPLIER_ZKEY_SHA256: &str =
    "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f";

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let mut session = Session::default();

    if !arguments.is_empty() {
        let tokens: Vec<&str> = arguments.iter().map(String::as_str).collect();
        return match run_command(&mut session, &tokens) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let interactive = io::stdin().is_terminal();
    if interactive {
        println!(
            "curvy-debug {} - rs-core debug REPL (type `help` for commands, `quit` or Ctrl-D to exit)",
            env!("CARGO_PKG_VERSION")
        );
    }
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        if interactive {
            print!("curvy> ");
            let _ = io::stdout().flush();
        }
        let Some(line) = lines.next() else { break };
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("error: {error}");
                break;
            }
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match run_command(&mut session, &tokens) {
            Ok(Flow::Quit) => break,
            Ok(Flow::Continue) => {}
            Err(error) => eprintln!("error: {error}"),
        }
    }
    ExitCode::SUCCESS
}

// Session state

/// Meta keys held for the session: private `k`/`v` hex + public `K`/`V` points.
struct MetaKeys {
    k_hex: String,
    v_hex: String,
    big_k: String,
    big_v: String,
}

/// A stealth announcement as it appears on the wire, plus the ephemeral `r`
/// and the announced one-time key when this session generated it.
struct Announcement {
    r_dec: Option<String>,
    big_r: String,
    view_tag: String,
    spending_pub_key: Option<String>,
}

struct SessionTree {
    depth: usize,
    imt: Imt,
}

#[derive(Default)]
struct Session {
    meta: Option<MetaKeys>,
    announcements: Vec<Announcement>,
    tree: Option<SessionTree>,
}

enum Flow {
    Continue,
    Quit,
}

// Dispatch

fn run_command(session: &mut Session, tokens: &[&str]) -> Result<Flow, String> {
    let Some((&command, rest)) = tokens.split_first() else {
        return Ok(Flow::Continue);
    };
    match command {
        "help" | "?" => {
            print_help();
            Ok(Flow::Continue)
        }
        "quit" | "exit" | "q" => Ok(Flow::Quit),
        "clear" => {
            // Clear the screen and scrollback.
            print!("\x1b[2J\x1b[3J\x1b[H");
            let _ = io::stdout().flush();
            Ok(Flow::Continue)
        }
        "session" => match rest {
            [] => {
                show_session(session);
                Ok(Flow::Continue)
            }
            ["clear"] => {
                *session = Session::default();
                println!("session cleared (meta keys, announcements, tree)");
                Ok(Flow::Continue)
            }
            _ => Err("usage: session [clear]".to_owned()),
        },
        "stealth" => cmd_stealth(session, rest).map(|()| Flow::Continue),
        "poseidon" => cmd_poseidon(rest).map(|()| Flow::Continue),
        "sha256" => cmd_sha256(rest).map(|()| Flow::Continue),
        "eddsa" => cmd_eddsa(rest).map(|()| Flow::Continue),
        "note" => cmd_note(rest).map(|()| Flow::Continue),
        "cipher" => cmd_cipher(rest).map(|()| Flow::Continue),
        "tree" => cmd_tree(session, rest).map(|()| Flow::Continue),
        "witness" => cmd_witness(session, rest).map(|()| Flow::Continue),
        "prove" => cmd_prove(rest).map(|()| Flow::Continue),
        other => Err(format!("unknown command {other:?} - type `help`")),
    }
}

fn print_help() {
    println!(
        "\
session state
  session                                   show session meta keys, announcements, tree
  session clear                             reset session state (meta keys, announcements, tree)
  clear                                     clear the screen
  quit | exit                               leave the REPL

stealth addressing (Domain A; k/v = private hex, K/V/S/R = \"X.Y\" points)
  stealth new-meta                          fresh meta keypair -> session
  stealth get-meta <k> <v>                  derive K/V from private keys -> session
  stealth send [<K> <V>]                    announce with a fresh ephemeral r (default: session keys)
  stealth send-r <r-dec> [<K> <V>]          deterministic announcement for a recorded r
  stealth add <R> <view-tag>                store an external announcement in the session
  stealth scan [<k> <v>] [<R> <tag> ..]     recover spending keys (defaults: session keys/announcements)
  stealth viewer-scan <v> <S> [<R> <tag> ..]  viewer flow: recover spending PUBLIC keys only
  stealth check <X.Y>                       is the point on BN254 G1 / secp256k1?
  stealth demo                              full sender -> recipient -> viewer round trip

domain-B primitives (field elements are canonical decimal strings)
  poseidon <dec> [.. up to 16]              Poseidon hash over BN254 Fr
  sha256 <dec> [..]                         sha256BigInt (raw 256-bit big-endian packing)
  eddsa pub <priv-hex>                      seed profile: secret scalar + public key
  eddsa sign <priv-hex> <msg-dec>           seed profile: EdDSA-Poseidon signature
  eddsa scalar-sign <scalar-dec> <msg-dec>  direct-scalar profile: sign + self-verify
  note <owner-x> <owner-y> <secret> <amount> <token>   ownerHash / id / nullifier
  cipher encrypt <amount> <token> <secret> <eph-x> <eph-y>
  cipher decrypt <enc-amount> <enc-token> <secret> <eph-x> <eph-y>

notes tree (session-stateful IMT)
  tree new [depth]                          fresh tree (default 30, the production depth)
  tree insert <leaf-dec> [..]               append leaves
  tree root | tree info                     current root / stats
  tree proof <index>                        inclusion proof for a leaf

witness builders (flat snarkjs input JSON)
  witness withdrawal-demo [amount] [token]  self-consistent withdrawal witness
  witness aggregation-demo                  2-in/1-out + fee-note aggregation witness
  witness pending-demo [<id-dec> ..]        pending-notes commitment batch (uses the session tree)

proving
  prove demo [a] [b]                        Groth16 prove + self-verify a*b on the committed fixture
                                            (real artifacts: use the curvy-native-prover binary)

Blank lines are skipped and `#` starts a comment, so scripts can be piped in."
    );
}

fn show_session(session: &Session) {
    match &session.meta {
        Some(meta) => {
            println!("meta keys:");
            println!("  k={}", meta.k_hex);
            println!("  v={}", meta.v_hex);
            println!("  K={}", meta.big_k);
            println!("  V={}", meta.big_v);
        }
        None => println!("meta keys: (none - `stealth new-meta`)"),
    }
    if session.announcements.is_empty() {
        println!("announcements: (none - `stealth send` / `stealth add`)");
    } else {
        println!("announcements:");
        for (index, announcement) in session.announcements.iter().enumerate() {
            println!(
                "  #{index} viewTag={} r={}",
                announcement.view_tag,
                announcement.r_dec.as_deref().unwrap_or("(unknown)")
            );
            println!("     R={}", announcement.big_r);
            if let Some(spending_pub_key) = &announcement.spending_pub_key {
                println!("     spendingPubKey={spending_pub_key}");
            }
        }
    }
    match &session.tree {
        Some(tree) => println!(
            "tree: depth={} leafCount={} root={}",
            tree.depth,
            tree.imt.leaf_count(),
            fr_to_dec(&tree.imt.root())
        ),
        None => println!("tree: (none - `tree new`)"),
    }
}

// Stealth

fn cmd_stealth(session: &mut Session, rest: &[&str]) -> Result<(), String> {
    match rest {
        ["new-meta"] => {
            let (k_hex, v_hex, big_k, big_v) = stealth::new_meta().map_err(|e| e.to_string())?;
            println!("k={k_hex}");
            println!("v={v_hex}");
            println!("K={big_k}");
            println!("V={big_v}");
            session.meta = Some(MetaKeys {
                k_hex,
                v_hex,
                big_k,
                big_v,
            });
            println!("(stored as session meta keys)");
            Ok(())
        }
        ["get-meta", k_hex, v_hex] => {
            let (big_k, big_v) = stealth::get_meta(k_hex, v_hex).map_err(|e| e.to_string())?;
            println!("K={big_k}");
            println!("V={big_v}");
            session.meta = Some(MetaKeys {
                k_hex: (*k_hex).to_owned(),
                v_hex: (*v_hex).to_owned(),
                big_k,
                big_v,
            });
            println!("(stored as session meta keys)");
            Ok(())
        }
        ["send", args @ ..] => {
            let (big_k, big_v) = resolve_meta_publics(session, args)?;
            let (r_dec, output) = stealth::send(&big_k, &big_v).map_err(|e| e.to_string())?;
            println!("r={r_dec}");
            record_announcement(session, Some(r_dec), output);
            Ok(())
        }
        ["send-r", r_dec, args @ ..] => {
            let (big_k, big_v) = resolve_meta_publics(session, args)?;
            let output = stealth::send_with_r(r_dec, &big_k, &big_v).map_err(|e| e.to_string())?;
            record_announcement(session, Some((*r_dec).to_owned()), output);
            Ok(())
        }
        ["add", big_r, view_tag] => {
            if !stealth::is_valid_bn254_point(big_r) {
                println!("warning: R is not a valid BN254 G1 point - scans will skip it");
            }
            if view_tag.len() != 2 {
                println!("warning: viewTag is not 2 hex chars - scans will treat it as a non-match");
            }
            session.announcements.push(Announcement {
                r_dec: None,
                big_r: (*big_r).to_owned(),
                view_tag: (*view_tag).to_owned(),
                spending_pub_key: None,
            });
            println!("(stored as announcement #{})", session.announcements.len() - 1);
            Ok(())
        }
        ["scan", args @ ..] => cmd_scan(session, args),
        ["viewer-scan", v_hex, big_s, pairs @ ..] => {
            let (rs, tags) = announcement_inputs(session, pairs)?;
            let matches = stealth::viewer_scan(v_hex, big_s, &rs, &tags).map_err(|e| e.to_string())?;
            if matches.is_empty() {
                println!("no candidates matched ({} announcement(s) scanned)", rs.len());
                return Ok(());
            }
            for candidate in &matches {
                println!("candidate index={}", candidate.index);
                println!("  spendingPubKey={}", candidate.spending_pub_key);
            }
            print_scan_summary(matches.len(), rs.len());
            Ok(())
        }
        ["check", point] => {
            println!("bn254G1={}", stealth::is_valid_bn254_point(point));
            println!("secp256k1={}", stealth::is_valid_secp256k1_point(point));
            Ok(())
        }
        ["demo"] => cmd_stealth_demo(session),
        _ => Err(
            "usage: stealth <new-meta|get-meta|send|send-r|add|scan|viewer-scan|check|demo> - see `help`"
                .to_owned(),
        ),
    }
}

fn resolve_meta_publics(session: &Session, args: &[&str]) -> Result<(String, String), String> {
    match args {
        [] => session_meta(session).map(|meta| (meta.big_k.clone(), meta.big_v.clone())),
        [big_k, big_v] => Ok(((*big_k).to_owned(), (*big_v).to_owned())),
        _ => Err("expected no key arguments (session meta) or exactly <K> <V>".to_owned()),
    }
}

fn session_meta(session: &Session) -> Result<&MetaKeys, String> {
    session.meta.as_ref().ok_or_else(|| {
        "no session meta keys - run `stealth new-meta` first or pass keys explicitly".to_owned()
    })
}

fn record_announcement(session: &mut Session, r_dec: Option<String>, output: stealth::SendOutput) {
    println!("R={}", output.big_r);
    println!("viewTag={}", output.view_tag);
    println!("spendingPubKey={}", output.spending_pub_key);
    session.announcements.push(Announcement {
        r_dec,
        big_r: output.big_r,
        view_tag: output.view_tag,
        spending_pub_key: Some(output.spending_pub_key),
    });
    println!(
        "(stored as announcement #{})",
        session.announcements.len() - 1
    );
}

fn cmd_scan(session: &Session, args: &[&str]) -> Result<(), String> {
    // "X.Y" points contain '.', while private hex scalars do not.
    let (k_hex, v_hex, pair_args): (String, String, &[&str]) =
        if args.first().is_some_and(|argument| argument.contains('.')) {
            let meta = session_meta(session)?;
            (meta.k_hex.clone(), meta.v_hex.clone(), args)
        } else {
            match args {
                [] => {
                    let meta = session_meta(session)?;
                    (meta.k_hex.clone(), meta.v_hex.clone(), &[])
                }
                [k_hex, v_hex, pairs @ ..] => ((*k_hex).to_owned(), (*v_hex).to_owned(), pairs),
                _ => return Err("usage: stealth scan [<k> <v>] [<R> <view-tag> ..]".to_owned()),
            }
        };
    let (rs, tags) = announcement_inputs(session, pair_args)?;
    let matches = stealth::scan(&k_hex, &v_hex, &rs, &tags).map_err(|e| e.to_string())?;
    if matches.is_empty() {
        println!(
            "no candidates matched ({} announcement(s) scanned)",
            rs.len()
        );
        return Ok(());
    }
    for candidate in &matches {
        println!("candidate index={}", candidate.index);
        println!("  spendingPubKey={}", candidate.spending_pub_key);
        println!("  spendingPrivKey={}", candidate.spending_priv_key);
    }
    print_scan_summary(matches.len(), rs.len());
    Ok(())
}

fn print_scan_summary(candidates: usize, scanned: usize) {
    println!(
        "{candidates} candidate(s) from {scanned} announcement(s); a viewTag match is a candidate \
         (~1/256 false positive), not proof of ownership"
    );
}

fn announcement_inputs(
    session: &Session,
    pairs: &[&str],
) -> Result<(Vec<String>, Vec<String>), String> {
    if pairs.is_empty() {
        if session.announcements.is_empty() {
            return Err(
                "no session announcements - run `stealth send`/`stealth add` first or pass <R> <view-tag> pairs"
                    .to_owned(),
            );
        }
        return Ok((
            session
                .announcements
                .iter()
                .map(|announcement| announcement.big_r.clone())
                .collect(),
            session
                .announcements
                .iter()
                .map(|announcement| announcement.view_tag.clone())
                .collect(),
        ));
    }
    if !pairs.len().is_multiple_of(2) {
        return Err("announcements come in <R> <view-tag> pairs".to_owned());
    }
    let mut rs = Vec::with_capacity(pairs.len() / 2);
    let mut tags = Vec::with_capacity(pairs.len() / 2);
    for pair in pairs.chunks_exact(2) {
        rs.push(pair[0].to_owned());
        tags.push(pair[1].to_owned());
    }
    Ok((rs, tags))
}

fn cmd_stealth_demo(session: &mut Session) -> Result<(), String> {
    println!("-- recipient: fresh meta keypair --");
    let (k_hex, v_hex, big_k, big_v) = stealth::new_meta().map_err(|e| e.to_string())?;
    println!("k={k_hex}");
    println!("v={v_hex}");
    println!("K={big_k}");
    println!("V={big_v}");

    println!("-- sender: send(K, V) announcement --");
    let (r_dec, output) = stealth::send(&big_k, &big_v).map_err(|e| e.to_string())?;
    println!("r={r_dec}");
    println!("R={}", output.big_r);
    println!("viewTag={}", output.view_tag);
    println!("spendingPubKey={}", output.spending_pub_key);

    println!("-- recipient: scan(k, v) over the announcement --");
    let rs = vec![output.big_r.clone()];
    let tags = vec![output.view_tag.clone()];
    let matches = stealth::scan(&k_hex, &v_hex, &rs, &tags).map_err(|e| e.to_string())?;
    let recovered = matches
        .first()
        .ok_or("scan did not match its own announcement - this is a bug")?;
    println!("spendingPrivKey={}", recovered.spending_priv_key);
    println!("spendingPubKey={}", recovered.spending_pub_key);
    if recovered.spending_pub_key != output.spending_pub_key {
        return Err(
            "recipient-derived spending pubkey does not match the announcement - this is a bug"
                .to_owned(),
        );
    }
    println!("recipient pubkey matches the sender's: true");

    println!("-- viewer: viewerScan(v, S=K) over the announcement --");
    let viewed = stealth::viewer_scan(&v_hex, &big_k, &rs, &tags).map_err(|e| e.to_string())?;
    let viewed = viewed
        .first()
        .ok_or("viewer scan did not match the announcement - this is a bug")?;
    println!("spendingPubKey={}", viewed.spending_pub_key);
    if viewed.spending_pub_key != output.spending_pub_key {
        return Err(
            "viewer-derived spending pubkey does not match the announcement - this is a bug"
                .to_owned(),
        );
    }
    println!("viewer pubkey matches the sender's: true");

    session.meta = Some(MetaKeys {
        k_hex,
        v_hex,
        big_k,
        big_v,
    });
    session.announcements.push(Announcement {
        r_dec: Some(r_dec),
        big_r: output.big_r,
        view_tag: output.view_tag,
        spending_pub_key: Some(output.spending_pub_key),
    });
    println!("(meta keys + announcement stored in the session; try `stealth scan` or `session`)");
    Ok(())
}

// Crypto primitives

fn cmd_poseidon(rest: &[&str]) -> Result<(), String> {
    if rest.is_empty() || rest.len() > 16 {
        return Err("poseidon takes 1..=16 decimal field elements".to_owned());
    }
    let inputs = rest
        .iter()
        .map(|value| parse_fr("input", value))
        .collect::<Result<Vec<_>, _>>()?;
    println!("poseidon{}={}", inputs.len(), fr_to_dec(&poseidon(&inputs)));
    Ok(())
}

fn cmd_sha256(rest: &[&str]) -> Result<(), String> {
    if rest.is_empty() {
        return Err("sha256 takes 1 or more decimal 256-bit integers".to_owned());
    }
    let inputs = rest
        .iter()
        .map(|value| parse_u256("input", value))
        .collect::<Result<Vec<_>, _>>()?;
    println!("sha256BigInt={}", sha256_bigint(&inputs));
    Ok(())
}

fn cmd_eddsa(rest: &[&str]) -> Result<(), String> {
    match rest {
        ["pub", private_hex] => {
            let public = eddsa::pub_from_private_key_hex(private_hex).map_err(|e| e.to_string())?;
            let bytes = from_hex_exact::<32>(private_hex).map_err(|e| e.to_string())?;
            println!("secretScalar={}", eddsa::derive_secret_scalar(&bytes));
            println!("publicKey.x={}", fr_to_dec(&public.0));
            println!("publicKey.y={}", fr_to_dec(&public.1));
            Ok(())
        }
        ["sign", private_hex, message] => {
            let message = parse_u256("message", message)?;
            let signature = eddsa::sign_hex(&message, private_hex).map_err(|e| e.to_string())?;
            println!("R8.x={}", fr_to_dec(&signature.r8.0));
            println!("R8.y={}", fr_to_dec(&signature.r8.1));
            println!("S={}", signature.s);
            Ok(())
        }
        ["scalar-sign", scalar_dec, message] => {
            let key = ScalarSigningKey::from_decimal(scalar_dec).map_err(|e| e.to_string())?;
            let message =
                Bn254Fr::try_from_dec(message).map_err(|error| format!("message: {error}"))?;
            let signature = key.sign_curvy_v1(message).map_err(|e| e.to_string())?;
            let public = key.verifying_key();
            println!("publicKey.x={}", fr_to_dec(&public.x()));
            println!("publicKey.y={}", fr_to_dec(&public.y()));
            println!("R8.x={}", fr_to_dec(&signature.r8.x()));
            println!("R8.y={}", fr_to_dec(&signature.r8.y()));
            println!("S={}", signature.s.as_biguint());
            println!(
                "selfVerified={}",
                verify_scalar_compat(message, public, &signature)
            );
            Ok(())
        }
        _ => Err("usage: eddsa <pub|sign|scalar-sign> - see `help`".to_owned()),
    }
}

fn cmd_note(rest: &[&str]) -> Result<(), String> {
    let [owner_x, owner_y, shared_secret, amount, token] = rest else {
        return Err("usage: note <owner-x> <owner-y> <shared-secret> <amount> <token>".to_owned());
    };
    let owner = (parse_fr("owner-x", owner_x)?, parse_fr("owner-y", owner_y)?);
    let shared_secret = parse_fr("shared-secret", shared_secret)?;
    let amount = parse_fr("amount", amount)?;
    let token = parse_fr("token", token)?;
    if !babyjubjub::is_in_subgroup(owner) {
        println!(
            "warning: owner point is not in the BabyJubjub subgroup (commitments computed anyway)"
        );
    }
    let owner_hash = note::owner_hash(owner, shared_secret);
    println!("ownerHash={}", fr_to_dec(&owner_hash));
    println!(
        "id={}",
        fr_to_dec(&note::note_id(owner_hash, amount, token))
    );
    println!(
        "nullifier={}",
        fr_to_dec(&note::nullifier(shared_secret, owner))
    );
    Ok(())
}

fn cmd_cipher(rest: &[&str]) -> Result<(), String> {
    match rest {
        ["encrypt", amount, token, shared_secret, eph_x, eph_y] => {
            let amount = parse_fr("amount", amount)?;
            let token = parse_fr("token", token)?;
            let shared_secret = parse_u256("shared-secret", shared_secret)?;
            let eph_x = parse_u256("eph-x", eph_x)?;
            let eph_y = parse_u256("eph-y", eph_y)?;
            let output = encrypt_amount_token(amount, token, &shared_secret, (&eph_x, &eph_y));
            println!("encryptedAmount={}", fr_to_dec(&output.encrypted_amount));
            println!("encryptedToken={}", fr_to_dec(&output.encrypted_token));
            Ok(())
        }
        [
            "decrypt",
            encrypted_amount,
            encrypted_token,
            shared_secret,
            eph_x,
            eph_y,
        ] => {
            let encrypted_amount = parse_fr("enc-amount", encrypted_amount)?;
            let encrypted_token = parse_fr("enc-token", encrypted_token)?;
            let shared_secret = parse_u256("shared-secret", shared_secret)?;
            let eph_x = parse_u256("eph-x", eph_x)?;
            let eph_y = parse_u256("eph-y", eph_y)?;
            let (amount, token) = decrypt_amount_token(
                encrypted_amount,
                encrypted_token,
                &shared_secret,
                (&eph_x, &eph_y),
            );
            println!("amount={}", fr_to_dec(&amount));
            println!("token={}", fr_to_dec(&token));
            println!("(remember: decrypt output is only trustworthy after the noteId recompute)");
            Ok(())
        }
        _ => Err("usage: cipher <encrypt|decrypt> - see `help`".to_owned()),
    }
}

// Notes tree

fn cmd_tree(session: &mut Session, rest: &[&str]) -> Result<(), String> {
    match rest {
        ["new"] => new_tree(session, NOTES_TREE_DEPTH),
        ["new", depth] => {
            let depth = parse_usize("depth", depth)?;
            if !(1..=32).contains(&depth) {
                return Err("depth must be in 1..=32".to_owned());
            }
            new_tree(session, depth)
        }
        ["insert", leaves @ ..] if !leaves.is_empty() => {
            let parsed = leaves
                .iter()
                .map(|leaf| parse_fr("leaf", leaf))
                .collect::<Result<Vec<_>, _>>()?;
            let tree = session_tree_mut(session)?;
            if let Ok(capacity) = tree.imt.capacity()
                && tree.imt.leaf_count() + parsed.len() > capacity
            {
                return Err(format!(
                    "tree is full: {} leaf slot(s) left, {} leaf(s) given",
                    capacity - tree.imt.leaf_count(),
                    parsed.len()
                ));
            }
            let start = tree.imt.leaf_count();
            for leaf in &parsed {
                tree.imt.insert(*leaf);
            }
            println!(
                "inserted {} leaf(s) at indices {}..{}",
                parsed.len(),
                start,
                tree.imt.leaf_count()
            );
            println!("root={}", fr_to_dec(&tree.imt.root()));
            Ok(())
        }
        ["root"] => {
            let tree = session_tree(session)?;
            println!("root={}", fr_to_dec(&tree.imt.root()));
            Ok(())
        }
        ["info"] => {
            let tree = session_tree(session)?;
            let capacity = tree.imt.capacity().map_or_else(
                |_| format!("2^{}", tree.depth),
                |capacity| capacity.to_string(),
            );
            println!("depth={}", tree.depth);
            println!("leafCount={}", tree.imt.leaf_count());
            println!("capacity={capacity}");
            println!("root={}", fr_to_dec(&tree.imt.root()));
            Ok(())
        }
        ["proof", index] => {
            let index = parse_usize("index", index)?;
            let tree = session_tree(session)?;
            if index >= tree.imt.leaf_count() {
                return Err(format!(
                    "index {index} out of range - the tree has {} leaf(s)",
                    tree.imt.leaf_count()
                ));
            }
            let proof = tree.imt.create_proof(index);
            println!("leaf={}", fr_to_dec(&proof.leaf));
            println!("index={}", proof.index);
            println!("root={}", fr_to_dec(&proof.root));
            let siblings: Vec<String> = proof.siblings.iter().map(fr_to_dec).collect();
            println!(
                "siblings={}",
                serde_json::to_string(&siblings).expect("strings serialize")
            );
            Ok(())
        }
        _ => Err("usage: tree <new|insert|root|info|proof> - see `help`".to_owned()),
    }
}

fn new_tree(session: &mut Session, depth: usize) -> Result<(), String> {
    let imt = Imt::new(depth);
    println!("created empty depth-{depth} tree");
    println!("root={}", fr_to_dec(&imt.root()));
    session.tree = Some(SessionTree { depth, imt });
    Ok(())
}

fn session_tree(session: &Session) -> Result<&SessionTree, String> {
    session
        .tree
        .as_ref()
        .ok_or_else(|| "no session tree - run `tree new` first".to_owned())
}

fn session_tree_mut(session: &mut Session) -> Result<&mut SessionTree, String> {
    session
        .tree
        .as_mut()
        .ok_or_else(|| "no session tree - run `tree new` first".to_owned())
}

// Witness builders

fn cmd_witness(session: &Session, rest: &[&str]) -> Result<(), String> {
    match rest {
        ["withdrawal-demo", args @ ..] if args.len() <= 2 => cmd_withdrawal_demo(args),
        ["aggregation-demo"] => cmd_aggregation_demo(),
        ["pending-demo", ids @ ..] => cmd_pending_demo(session, ids),
        _ => Err(
            "usage: witness <withdrawal-demo|aggregation-demo|pending-demo> - see `help`"
                .to_owned(),
        ),
    }
}

/// Builds a deterministic demo note with salt-derived keys.
fn demo_note(signer: &impl NoteSigner, amount: Fr, token: Fr, salt: u64) -> Note {
    let salt = fr_from_dec(&salt.to_string());
    Note {
        amount,
        token,
        owner_pub: signer.public_key(),
        shared_secret: poseidon(&[fr_from_dec("42"), salt]),
        ephemeral_key: (
            poseidon(&[fr_from_dec("7"), salt]),
            poseidon(&[fr_from_dec("8"), salt]),
        ),
        view_tag: fr_from_dec("1"),
    }
}

fn print_note(label: &str, note: &Note) {
    println!(
        "{label}: amount={} token={}",
        fr_to_dec(&note.amount),
        fr_to_dec(&note.token)
    );
    println!("  ownerHash={}", fr_to_dec(&note.owner_hash()));
    println!("  id={}", fr_to_dec(&note.id()));
    println!("  nullifier={}", fr_to_dec(&note.nullifier()));
}

fn cmd_withdrawal_demo(args: &[&str]) -> Result<(), String> {
    let amount = parse_fr("amount", args.first().copied().unwrap_or("1000"))?;
    let token = parse_fr("token", args.get(1).copied().unwrap_or("1"))?;

    let signer = SeedNoteSigner::new(DEMO_OWNER_SEED_HEX).map_err(|e| e.to_string())?;
    let note = demo_note(&signer, amount, token, 1);
    println!("owner: seed-backed demo account ({DEMO_OWNER_SEED_HEX})");
    print_note("input note", &note);

    let mut imt = Imt::new(NOTES_TREE_DEPTH);
    imt.insert(note.id());
    let inclusion = imt.create_proof(0);
    let proof = Proof {
        leaf_index: 0,
        siblings: inclusion.siblings,
    };

    let destination = fr_from_dec("3735928559"); // 0xDEADBEEF stand-in address
    let witness = witness::build_withdrawal_with_signer(
        std::slice::from_ref(&note),
        &signer,
        &[proof],
        imt.root(),
        destination,
        token,
    )
    .map_err(|e| e.to_string())?;
    println!("{}", pretty(&witness)?);
    Ok(())
}

fn cmd_aggregation_demo() -> Result<(), String> {
    let owner = SeedNoteSigner::new(DEMO_OWNER_SEED_HEX).map_err(|e| e.to_string())?;
    let fee_owner = SeedNoteSigner::new(DEMO_FEE_SEED_HEX).map_err(|e| e.to_string())?;
    let token = fr_from_dec("1");

    let inputs = [
        demo_note(&owner, fr_from_dec("600"), token, 1),
        demo_note(&owner, fr_from_dec("500"), token, 2),
    ];
    let output = demo_note(&owner, fr_from_dec("1090"), token, 3);
    let fee_note = demo_note(&fee_owner, fr_from_dec("10"), token, 4);

    println!("owner: seed-backed demo account ({DEMO_OWNER_SEED_HEX})");
    print_note("input note 0", &inputs[0]);
    print_note("input note 1", &inputs[1]);
    print_note("output note", &output);
    print_note("fee note", &fee_note);

    let mut imt = Imt::new(NOTES_TREE_DEPTH);
    for note in &inputs {
        imt.insert(note.id());
    }
    // Proofs are created only after every insert so all siblings match the final root.
    let proofs: Vec<Proof> = (0..inputs.len())
        .map(|index| Proof {
            leaf_index: index as u64,
            siblings: imt.create_proof(index).siblings,
        })
        .collect();

    let witness = witness::build_aggregation_with_signer(
        &inputs,
        &proofs,
        std::slice::from_ref(&output),
        &fee_note,
        &owner,
        imt.root(),
        fr_from_dec("9"),
        fr_from_dec("1"),
        fee_owner.public_key(),
    )
    .map_err(|e| e.to_string())?;
    println!("(shape demo - amounts are not balanced against circuit constraints here)");
    println!("{}", pretty(&witness)?);
    Ok(())
}

fn cmd_pending_demo(session: &Session, id_args: &[&str]) -> Result<(), String> {
    let ids: Vec<Fr> = if id_args.is_empty() {
        ["1", "2", "3"].iter().map(|id| fr_from_dec(id)).collect()
    } else {
        id_args
            .iter()
            .map(|id| parse_fr("note id", id))
            .collect::<Result<_, _>>()?
    };
    let batch_size = ids.len().max(4);

    let fallback;
    let (imt, depth, source) = match session.tree.as_ref() {
        Some(tree) => (&tree.imt, tree.depth, "session tree"),
        None => {
            fallback = Imt::new(NOTES_TREE_DEPTH);
            (&fallback, NOTES_TREE_DEPTH, "fresh production-depth tree")
        }
    };
    println!(
        "base: {source} (leafCount={}, root={})",
        imt.leaf_count(),
        fr_to_dec(&imt.root())
    );
    println!("batchSize={batch_size} (unused slots are zero-id skips)");
    let witness = witness::build_pending_commitment(imt, depth, batch_size, &ids);
    println!("{}", pretty(&witness)?);
    println!("(the session tree is unchanged - the builder works on a copy)");
    Ok(())
}

// Proving

fn cmd_prove(rest: &[&str]) -> Result<(), String> {
    let ["demo", args @ ..] = rest else {
        return Err(
            "usage: prove demo [a] [b] - for real circuit artifacts use the curvy-native-prover binary"
                .to_owned(),
        );
    };
    let (a, b) = match args {
        [] => ("3".to_owned(), "11".to_owned()),
        [a, b] => (fr_to_dec(&parse_fr("a", a)?), fr_to_dec(&parse_fr("b", b)?)),
        _ => return Err("usage: prove demo [a] [b]".to_owned()),
    };

    let graph = multiplier_graph();
    let graph_sha256 = sha256_hex(&graph);
    println!(
        "fixture: multiplier.zkey ({} bytes, sha256 {MULTIPLIER_ZKEY_SHA256})",
        MULTIPLIER_ZKEY.len()
    );

    let started = Instant::now();
    let prover = CircuitProver::from_artifacts(
        MULTIPLIER_ZKEY,
        MULTIPLIER_ZKEY_SHA256,
        &graph,
        &graph_sha256,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "artifacts authenticated + parsed in {:.1} ms (constraints={}, publicInputs={})",
        elapsed_ms(started),
        prover.num_constraints(),
        prover.num_public()
    );

    let input_json = format!(r#"{{"a":"{a}","b":"{b}"}}"#);
    println!("input={input_json}");
    let started = Instant::now();
    let assignment = prover
        .calculate_witness_json(&input_json)
        .map_err(|e| e.to_string())?;
    println!(
        "witness calculated in {:.1} ms ({} signals)",
        elapsed_ms(started),
        assignment.len()
    );

    let started = Instant::now();
    let bundle = prover
        .prove_assignment(&assignment)
        .map_err(|e| e.to_string())?;
    println!("proved + self-verified in {:.1} ms", elapsed_ms(started));
    println!("publicSignals={}", bundle.public_signals_json);
    println!("proof={}", pretty_json_str(&bundle.proof_json));
    Ok(())
}

/// Builds the witness graph shared with the prover tests.
fn multiplier_graph() -> Vec<u8> {
    let mut graph = Vec::new();

    graph.extend_from_slice(b"CVYWIT01");
    graph.extend_from_slice(&1_u16.to_le_bytes());
    graph.extend_from_slice(&1_u16.to_le_bytes());
    graph.extend_from_slice(&64_u32.to_le_bytes());
    graph.extend_from_slice(&[0_u8; 32]);
    graph.extend_from_slice(&4_u32.to_le_bytes());
    graph.extend_from_slice(&4_u32.to_le_bytes());
    graph.extend_from_slice(&2_u32.to_le_bytes());
    graph.extend_from_slice(&3_u32.to_le_bytes());

    for input in 0_u32..=2 {
        graph.push(0);
        graph.extend_from_slice(&input.to_le_bytes());
    }
    graph.push(2);
    graph.push(0);
    graph.extend_from_slice(&1_u32.to_le_bytes());
    graph.extend_from_slice(&2_u32.to_le_bytes());

    for signal in [0_u32, 3, 1, 2] {
        graph.extend_from_slice(&signal.to_le_bytes());
    }
    for (name, signal) in [("a", 1_u32), ("b", 2_u32)] {
        graph.extend_from_slice(&fnv1a(name).to_le_bytes());
        graph.extend_from_slice(&signal.to_le_bytes());
        graph.extend_from_slice(&1_u32.to_le_bytes());
    }

    graph
}

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF29CE484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3)
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// Parsing and formatting

fn parse_fr(label: &str, value: &str) -> Result<Fr, String> {
    Bn254Fr::try_from_dec(value)
        .map(Bn254Fr::into_inner)
        .map_err(|error| format!("{label} {value:?}: {error}"))
}

fn parse_u256(label: &str, value: &str) -> Result<BigUint, String> {
    let parsed = BigUint::from_str(value)
        .map_err(|_| format!("{label} {value:?}: expected an unsigned decimal integer"))?;
    if parsed.bits() > 256 {
        return Err(format!("{label} {value:?}: exceeds 256 bits"));
    }
    Ok(parsed)
}

fn parse_usize(label: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|_| format!("{label} {value:?}: expected a small unsigned integer"))
}

fn pretty(witness: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_string_pretty(witness).map_err(|error| error.to_string())
}

fn pretty_json_str(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .and_then(|value| serde_json::to_string_pretty(&value))
        .unwrap_or_else(|_| json.to_owned())
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}
