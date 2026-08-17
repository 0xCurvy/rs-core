import { readFileSync } from "node:fs";

const wasmDeclarations = [
  "crates/wasm/pkg-node/curvy_wasm.d.ts",
  "crates/prover/pkg-node/curvy_prover.d.ts",
]
  .map((file) => readFileSync(file, "utf8"))
  .join("\n");
const ffiHeader = readFileSync("bindings/ffi/include/curvy.h", "utf8");

const required = {
  functions: {
    dbg_isValidBN254Point: "curvy_is_valid_bn254_point",
    dbg_isValidSECP256k1Point: "curvy_is_valid_secp256k1_point",
    decryptAmountToken: "curvy_decrypt_amount_token",
    encryptAmountToken: "curvy_encrypt_amount_token",
    ephemeralPubKey: "curvy_ephemeral_pub_key",
    get_meta: "curvy_get_meta",
    new_meta: "curvy_new_meta",
    noteId: "curvy_note_id",
    notesShardHeight: "curvy_notes_shard_height",
    notesShardSize: "curvy_notes_shard_size",
    notesTreeDepth: "curvy_notes_tree_depth",
    notesTreeVersion: "curvy_notes_tree_version",
    nullifier: "curvy_nullifier",
    ownerHash: "curvy_owner_hash",
    poseidon: "curvy_poseidon",
    pubFromPrivateKey: "curvy_pub_from_private_key",
    pubFromScalar: "curvy_pub_from_scalar",
    scan: "curvy_scan",
    send: "curvy_send",
    sha256BigInt: "curvy_sha256_bigint",
    sign: "curvy_sign",
    signWithScalar: "curvy_sign_with_scalar",
    verifyMerkleProof: "curvy_verify_merkle_proof",
    verifyScalarSignature: "curvy_verify_scalar_signature",
    version: "curvy_version",
    viewerScan: "curvy_viewer_scan",
  },
  classes: {
    MerkleTree: {
      constructor: "curvy_merkle_new",
      free: "curvy_merkle_free",
      fromLeaves: "curvy_merkle_from_leaves",
      getIndex: "curvy_merkle_get_index",
      insert: "curvy_merkle_insert",
      insertMany: "curvy_merkle_insert_many",
      leaves: "curvy_merkle_leaves",
      proof: "curvy_merkle_proof",
      proofAt: "curvy_merkle_proof_at",
      root: "curvy_merkle_root",
      truncate: "curvy_merkle_truncate",
      depth: "curvy_merkle_depth",
      leafCount: "curvy_merkle_leaf_count",
    },
    NotesFrontier: {
      constructor: "curvy_frontier_new",
      free: "curvy_frontier_free",
      append: "curvy_frontier_append",
      appendMany: "curvy_frontier_append_many",
      production: "curvy_frontier_production",
      restore: "curvy_frontier_restore",
      root: "curvy_frontier_root",
      snapshot: "curvy_frontier_snapshot",
      depth: "curvy_frontier_depth",
      leafCount: "curvy_frontier_leaf_count",
      shardCount: "curvy_frontier_shard_count",
      shardHeight: "curvy_frontier_shard_height",
      shardSize: "curvy_frontier_shard_size",
    },
    NotesFrontierAppend: {
      free: "curvy_frontier_append",
      completedShardIndex: "curvy_frontier_append",
      completedShardRoot: "curvy_frontier_append",
      hasCompletedShard: "curvy_frontier_append",
      leafIndex: "curvy_frontier_append",
    },
    NotesFrontierCompletedShard: {
      free: "curvy_frontier_append_many",
      root: "curvy_frontier_append_many",
      shardIndex: "curvy_frontier_append_many",
    },
    OrderedMerkleTree: {
      constructor: "curvy_ordered_new",
      free: "curvy_ordered_free",
      fromLeaves: "curvy_ordered_from_leaves",
      insert: "curvy_ordered_insert",
      insertMany: "curvy_ordered_insert_many",
      proofAt: "curvy_ordered_proof_at",
      root: "curvy_ordered_root",
      depth: "curvy_ordered_depth",
      leafCount: "curvy_ordered_leaf_count",
    },
    ScanMatch: {
      free: "curvy_scan",
      index: "curvy_scan",
      spendingPrivKey: "curvy_scan",
      spendingPubKey: "curvy_scan",
    },
    ShardedInclusionProof: {
      free: "curvy_proof_free",
      index: "curvy_proof_index",
      leaf: "curvy_proof_leaf",
      root: "curvy_proof_root",
      siblings: "curvy_proof_siblings",
    },
    ShardedNotesTree: {
      constructor: "curvy_sharded_new",
      free: "curvy_sharded_free",
      adoptFrozenWitness: "curvy_sharded_adopt_frozen_witness",
      append: "curvy_sharded_append",
      appendMany: "curvy_sharded_append_many",
      completedShardRoot: "curvy_sharded_completed_shard_root",
      completedShardRoots: "curvy_sharded_completed_shard_roots",
      drainDirtyOwnedNotes: "curvy_sharded_drain_dirty_owned_notes",
      liveLeaves: "curvy_sharded_live_leaves",
      markOwned: "curvy_sharded_mark_owned",
      ownedNotes: "curvy_sharded_owned_notes",
      restore: "curvy_sharded_restore",
      restoreParts: "curvy_sharded_restore_parts",
      rewindLiveTo: "curvy_sharded_rewind_live_to",
      root: "curvy_sharded_root",
      snapshot: "curvy_sharded_snapshot",
      unmarkOwned: "curvy_sharded_unmark_owned",
      witness: "curvy_sharded_witness",
      completedShardCount: "curvy_sharded_completed_shard_count",
      depth: "curvy_sharded_depth",
      leafCount: "curvy_sharded_leaf_count",
      ownedNoteCount: "curvy_sharded_owned_note_count",
      shardHeight: "curvy_sharded_shard_height",
      shardSize: "curvy_sharded_shard_size",
    },
    ShardedOwnedNoteWitness: {
      free: "curvy_sharded_owned_notes",
      frozen: "curvy_sharded_owned_notes",
      leafIndex: "curvy_sharded_owned_notes",
      noteId: "curvy_sharded_owned_notes",
      withinShardSiblings: "curvy_sharded_owned_notes",
    },
    ViewerMatch: {
      free: "curvy_viewer_scan",
      index: "curvy_viewer_scan",
      spendingPubKey: "curvy_viewer_scan",
    },
    WasmCircuitProver: {
      constructor: "curvy_circuit_prover_new",
      free: "curvy_circuit_prover_free",
      prove: "curvy_circuit_prover_prove",
      numConstraints: "curvy_circuit_prover_num_constraints",
      numPublic: "curvy_circuit_prover_num_public",
    },
    WasmProver: {
      constructor: "curvy_prover_new",
      free: "curvy_prover_free",
      prove: "curvy_prover_prove",
      numConstraints: "curvy_prover_num_constraints",
      numPublic: "curvy_prover_num_public",
    },
    WasmWitnessGraph: {
      constructor: "curvy_witness_graph_new",
      free: "curvy_witness_graph_free",
      calculate: "curvy_witness_graph_calculate",
      assignmentSize: "curvy_witness_graph_assignment_size",
    },
  },
};

const wasmFunctions = new Set(
  [...wasmDeclarations.matchAll(/^export function ([A-Za-z0-9_]+)\(/gm)].map((match) => match[1]),
);
const wasmClasses = new Map(
  [...wasmDeclarations.matchAll(/^export class ([A-Za-z0-9_]+) \{([\s\S]*?)^\}/gm)].map((match) => {
    const members = new Set();
    for (const line of match[2].split("\n")) {
      if (line.includes("[Symbol.dispose]")) continue;
      if (/^\s*private\s+constructor\(/.test(line)) continue;
      const method = line.match(/^\s*(?:static\s+)?(?:private\s+)?([A-Za-z0-9_]+)\(/);
      const property = line.match(/^\s*readonly\s+([A-Za-z0-9_]+):/);
      if (method) members.add(method[1]);
      if (property) members.add(property[1]);
    }
    return [match[1], members];
  }),
);
const ffiSymbols = new Set(
  [...ffiHeader.matchAll(/\b(curvy_[a-z0-9_]+)\s*\(/g)].map((match) => match[1]),
);

const errors = [];
for (const name of wasmFunctions) {
  const ffiSymbol = required.functions[name];
  if (!ffiSymbol) errors.push(`unmapped WASM function: ${name}`);
  else if (!ffiSymbols.has(ffiSymbol)) errors.push(`missing FFI symbol ${ffiSymbol} for ${name}`);
}
// A removed WASM function must not leave a dead mapping behind, or the next
// reader takes the table as proof of a surface that no longer exists.
for (const name of Object.keys(required.functions)) {
  if (!wasmFunctions.has(name)) errors.push(`stale FFI function mapping: ${name}`);
}
for (const [className, members] of wasmClasses) {
  const mappings = required.classes[className];
  if (!mappings) {
    errors.push(`unmapped WASM class: ${className}`);
    continue;
  }
  for (const member of members) {
    if (!Object.hasOwn(mappings, member)) {
      errors.push(`unmapped WASM class member: ${className}.${member}`);
      continue;
    }
    const symbol = mappings[member];
    if (!ffiSymbols.has(symbol)) errors.push(`missing FFI symbol ${symbol} for ${className}.${member}`);
  }
  for (const member of Object.keys(mappings)) {
    if (!members.has(member)) errors.push(`stale FFI class mapping: ${className}.${member}`);
  }
}

if (errors.length > 0) {
  throw new Error(`WASM/FFI surface drift:\n${errors.map((error) => `- ${error}`).join("\n")}`);
}

const classMemberCount = [...wasmClasses.values()].reduce((total, members) => total + members.size, 0);
console.log(
  `FFI covers ${wasmFunctions.size} WASM functions and ${classMemberCount} members across ${wasmClasses.size} WASM classes`,
);
