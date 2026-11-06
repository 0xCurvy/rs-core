//! Version 2 evaluates exactly like version 1.
//!
//! `roundtrip.rs` checks that both encodings of a few fixed graphs load and agree.
//! These tests generate graphs instead: every operation, inputs of several widths,
//! constants at the field's edges, references and output deltas at every varint
//! length the decoder distinguishes. Each graph is encoded in both versions, loaded
//! by both evaluators, evaluated on the same inputs and transcoded both ways; any
//! difference in acceptance, assignment, error or bytes fails the test.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use curvy_signet::postcard::{ALL_OPERATIONS, Graph, InputMapping, Node, Operation};
use curvy_signet::{Envelope, FormatVersion, encode, hex};
use curvy_witness::sage::SageGraph;
use curvy_witness::{Limits, WitnessGraph, WitnessWorkspace};
use num_bigint::{BigInt, BigUint};
use ruint::aliases::U256;
use sha2::{Digest, Sha256};

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF2_9CE4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01B3)
    })
}

/// splitmix64: fixed seeds, so a failure names the case that reproduces it.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    /// A canonical scalar, biased towards the values operations treat specially.
    fn field(&mut self) -> U256 {
        let modulus = U256::from_limbs(Fr::MODULUS.0);
        match self.below(8) {
            0 => U256::ZERO,
            1 => U256::from(1_u64),
            2 => modulus - U256::from(1_u64),
            3 => modulus - U256::from(1 + self.below(300) as u64),
            4 => U256::from(self.below(300) as u64),
            5 => U256::from(1_u64) << self.below(254),
            _ => U256::from_limbs([self.next(), self.next(), self.next(), self.next()]) % modulus,
        }
    }
}

/// Small constants every generated graph carries at nodes 1 to 8, so shifts and
/// divisions usually take operands they do not reject.
const SMALL: [u64; 8] = [0, 1, 2, 3, 7, 64, 253, 255];
/// Node index of a nonzero entry of [`SMALL`].
fn nonzero_small(rng: &mut Rng) -> usize {
    2 + rng.below(SMALL.len() - 1)
}

struct Case {
    graph: Graph,
    inputs: Vec<(String, usize)>,
}

fn random_case(rng: &mut Rng, extra_nodes: usize) -> Case {
    let mut inputs = Vec::new();
    let mut input_mapping = Vec::new();
    let mut next_signal = 1;
    for index in 0..1 + rng.below(4) {
        let name = format!("in{index}");
        let size = 1 + rng.below(3);
        input_mapping.push(InputMapping {
            hash: fnv1a(&name),
            signal_id: next_signal as u64,
            signal_size: size as u64,
        });
        inputs.push((name, size));
        next_signal += size;
    }
    // Sometimes leave inputs at the end of the buffer that no name covers.
    let buffer = next_signal + rng.below(2);

    let mut nodes = vec![Node::Constant(U256::from(1_u64))];
    nodes.extend(SMALL.iter().map(|&value| Node::Constant(U256::from(value))));
    for index in nodes.len()..nodes.len() + extra_nodes {
        let prior = |rng: &mut Rng| {
            // Mostly near, sometimes anywhere, so varints of every length occur.
            if rng.chance(70) {
                index - 1 - rng.below(index.min(8))
            } else {
                rng.below(index)
            }
        };
        nodes.push(match rng.below(20) {
            0..=2 => Node::Input(rng.below(buffer)),
            3 => Node::Constant(rng.field()),
            4 => Node::Bbf(format!("bbf_inv_{index}"), vec![prior(rng)]),
            _ => {
                let operation = ALL_OPERATIONS[rng.below(ALL_OPERATIONS.len())];
                let mut left = prior(rng);
                let right = match operation {
                    Operation::Shl | Operation::Shr if rng.chance(90) => 1 + rng.below(SMALL.len()),
                    Operation::Div | Operation::Mod | Operation::IDiv if rng.chance(90) => {
                        nonzero_small(rng)
                    }
                    _ => prior(rng),
                };
                if operation == Operation::Inv && rng.chance(80) {
                    left = nonzero_small(rng);
                }
                Node::Op(operation, left, right)
            }
        });
    }

    let mut signals = vec![0];
    for _ in 0..1 + rng.below(40) {
        signals.push(rng.below(nodes.len()));
    }
    Case {
        graph: Graph {
            nodes,
            signals,
            input_mapping,
        },
        inputs,
    }
}

fn random_input(rng: &mut Rng, inputs: &[(String, usize)]) -> String {
    let value = |rng: &mut Rng| {
        if rng.chance(10) {
            format!("\"-{}\"", rng.below(1000))
        } else {
            format!("\"{}\"", rng.field())
        }
    };
    let fields = inputs
        .iter()
        .map(|(name, size)| {
            if *size == 1 && rng.chance(50) {
                format!("\"{name}\":{}", value(rng))
            } else {
                let values = (0..*size).map(|_| value(rng)).collect::<Vec<_>>();
                format!("\"{name}\":[{}]", values.join(","))
            }
        })
        .collect::<Vec<_>>();
    format!("{{{}}}", fields.join(","))
}

fn pin(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

type Outcome = Result<Vec<Fr>, String>;

/// Load `bytes` in both evaluators and evaluate `input` in each; they must agree.
fn evaluate(bytes: &[u8], input: &str, label: &str) -> Outcome {
    let limits = Limits::batch_prover();
    let graph = WitnessGraph::from_bytes_with_limits(bytes, &pin(bytes), limits)
        .unwrap_or_else(|error| panic!("{label}: the evaluator refused the export: {error}"));
    let sage = SageGraph::from_bytes_with_limits(bytes, &pin(bytes), limits)
        .unwrap_or_else(|error| panic!("{label}: SAGE refused the export: {error}"));
    let outcome = graph.calculate_json(input).map_err(|e| e.to_string());
    assert_eq!(
        sage.calculate_json(input).map_err(|e| e.to_string()),
        outcome,
        "{label}: SAGE and the default evaluator disagree"
    );
    outcome
}

/// Everything a v2 artifact must share with its v1 twin.
fn check_parity(case: &Case, rng: &mut Rng, label: &str) -> usize {
    let envelope = if rng.chance(20) {
        Envelope::Cvywit
    } else {
        Envelope::Signet
    };
    let digest = [rng.next() as u8; 32];
    let v1 = encode(&case.graph, digest, envelope, FormatVersion::V1).expect("encode v1");
    let v2 = encode(&case.graph, digest, envelope, FormatVersion::V2).expect("encode v2");
    assert_eq!(v1[..8], v2[..8], "{label}: envelope");
    assert_eq!(v1[10..64], v2[10..64], "{label}: header past the version");

    assert_eq!(
        curvy_signet::transcode(&v1, FormatVersion::V2).expect("transcode v1"),
        v2,
        "{label}: transcoding v1 is not the v2 export"
    );
    assert_eq!(
        curvy_signet::transcode(&v2, FormatVersion::V1).expect("transcode v2"),
        v1,
        "{label}: transcoding v2 is not the v1 export"
    );

    let compressed = rng.chance(25).then(|| {
        ruzstd::encoding::compress_to_vec(
            v2.as_slice(),
            ruzstd::encoding::CompressionLevel::Fastest,
        )
    });

    let mut evaluated = 0;
    for _ in 0..3 {
        let input = random_input(rng, &case.inputs);
        let expected = evaluate(&v1, &input, label);
        assert_eq!(
            evaluate(&v2, &input, label),
            expected,
            "{label}: v2 evaluates differently from v1 on {input}"
        );
        if let Some(compressed) = &compressed {
            assert_eq!(
                evaluate(compressed, &input, label),
                expected,
                "{label}: compressed v2 evaluates differently on {input}"
            );
        }
        evaluated += usize::from(expected.is_ok());
    }
    evaluated
}

#[test]
fn random_graphs_evaluate_alike_in_both_versions() {
    let mut evaluated = 0;
    let mut operations_seen = [false; ALL_OPERATIONS.len()];
    for seed in 0..600_u64 {
        let mut rng = Rng(seed);
        let extra_nodes = 1 + rng.below(200);
        let case = random_case(&mut rng, extra_nodes);
        for node in &case.graph.nodes {
            if let Node::Op(operation, ..) = node {
                let index = ALL_OPERATIONS.iter().position(|o| o == operation).unwrap();
                operations_seen[index] = true;
            }
        }
        evaluated += check_parity(&case, &mut rng, &format!("seed {seed}"));
    }
    assert!(
        operations_seen.iter().all(|&seen| seen),
        "every operation occurs"
    );
    // Errors (a zero divisor, a shift out of range) must match too, but most
    // evaluations have to complete for the assignments to be compared at all.
    assert!(
        evaluated > 900,
        "only {evaluated} of 1,800 evaluations completed"
    );
}

#[test]
fn large_random_graphs_evaluate_alike_in_both_versions() {
    for seed in 1_000..1_004_u64 {
        let mut rng = Rng(seed);
        let case = random_case(&mut rng, 40_000);
        check_parity(&case, &mut rng, &format!("seed {seed}"));
    }
}

/// Every varint length a reference or an output delta can take, at its edges.
///
/// Node `i` of the chain holds the value `i + 1`, so a reference that lands one
/// node off is visible in the assignment, not only as a difference between
/// versions.
#[test]
fn references_and_output_deltas_at_every_varint_boundary() {
    // Backward distances: one byte up to 127, two to 16,383, three to 2,097,151.
    const DISTANCES: [usize; 8] = [1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, 2_200_000];
    const CHAIN: usize = 2_200_002;

    // 0: one; 1..CHAIN: node i = node (i - 1) + one, so it holds i + 1.
    let mut nodes = vec![Node::Constant(U256::from(1_u64))];
    for index in 1..CHAIN {
        nodes.push(Node::Op(Operation::Add, index - 1, 0));
    }
    // Probe d reads the node d back from itself: the chain node holding that value.
    let mut expected = Vec::new();
    for distance in DISTANCES {
        let index = nodes.len();
        let target = index - distance;
        nodes.push(Node::Op(Operation::Mul, target, 0));
        expected.push((index, target as u64 + 1));
    }
    // The inverse record takes the same distances.
    for distance in DISTANCES {
        let index = nodes.len();
        nodes.push(Node::Bbf(
            format!("bbf_inv_{index}"),
            vec![index - distance],
        ));
    }

    // Output deltas around each ZigZag length: ±63/64 (one byte), ±8,191/8,192
    // (two), ±1,048,575/1,048,576 (three) and a three-byte negative jump back.
    let mut signals = vec![0];
    let mut current = 1_100_000_i64;
    signals.push(current as usize);
    for delta in [
        63_i64, 64, -64, -65, 8_191, 8_192, -8_192, -8_193, 1_048_575, -1_048_576, -1_048_577,
        1_048_576, 0, -1,
    ] {
        current += delta;
        signals.push(current as usize);
    }
    for (index, _) in &expected {
        signals.push(*index);
    }

    let graph = Graph {
        nodes,
        signals: signals.clone(),
        input_mapping: vec![InputMapping {
            hash: fnv1a("unused"),
            signal_id: 1,
            signal_size: 1,
        }],
    };
    let v1 = encode(&graph, [7; 32], Envelope::Signet, FormatVersion::V1).expect("encode v1");
    let v2 = encode(&graph, [7; 32], Envelope::Signet, FormatVersion::V2).expect("encode v2");
    assert_eq!(curvy_signet::transcode(&v1, FormatVersion::V2).unwrap(), v2);
    assert_eq!(curvy_signet::transcode(&v2, FormatVersion::V1).unwrap(), v1);

    let limits = Limits::batch_prover();
    let input = r#"{"unused":"5"}"#;
    let assignment = |bytes: &[u8]| {
        WitnessGraph::from_bytes_with_limits(bytes, &pin(bytes), limits)
            .expect("load")
            .calculate_json(input)
            .expect("evaluate")
    };
    let from_v1 = assignment(&v1);
    assert_eq!(assignment(&v2), from_v1, "v2 evaluates differently from v1");

    let value = |index: usize| -> u64 {
        let bigint = from_v1[signals.iter().position(|&s| s == index).unwrap()].into_bigint();
        assert!(bigint.to_bytes_le()[8..].iter().all(|&b| b == 0));
        bigint.0[0]
    };
    for (index, target) in expected {
        assert_eq!(value(index), target, "probe at node {index}");
    }
    for &signal in &signals[1..1 + 15] {
        assert_eq!(value(signal), signal as u64 + 1, "output {signal}");
    }
}

// ---------------------------------------------------------------------------
// An independent oracle.
//
// The tests above compare the two versions with each other. These compare them
// with what the operations mean: each graph is built together with the value of
// every node, computed here with `num-bigint` rather than with the evaluator's
// field code, and every encoding and evaluator path must reproduce it - or fail
// with the same error at the same node.
// ---------------------------------------------------------------------------

fn modulus() -> BigUint {
    BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le())
}

fn to_u256(value: &BigUint) -> U256 {
    let mut bytes = value.to_bytes_le();
    bytes.resize(32, 0);
    U256::from_le_slice(&bytes)
}

/// A scalar from the values the operations treat specially, or a random one.
fn edge_value(rng: &mut Rng) -> BigUint {
    let p = modulus();
    let half = (&p - 1_u32) / 2_u32;
    let two = BigUint::from(2_u32);
    if rng.below(3) == 0 {
        let bytes = (0..32).map(|_| rng.next() as u8).collect::<Vec<_>>();
        return BigUint::from_bytes_le(&bytes) % &p;
    }
    let edges = [
        BigUint::from(0_u32),
        BigUint::from(1_u32),
        BigUint::from(2_u32),
        BigUint::from(3_u32),
        &p - 1_u32,
        &p - 2_u32,
        half.clone(),
        &half + 1_u32,
        &half - 1_u32,
        two.pow(253),
        two.pow(253) - 1_u32,
        two.pow(128),
        two.pow(64),
        two.pow(64) - 1_u32,
        BigUint::from(253_u32),
        BigUint::from(254_u32),
        BigUint::from(255_u32),
        BigUint::from(256_u32),
        &p - 255_u32,
        &p - 256_u32,
    ];
    edges[rng.below(edges.len())].clone() % &p
}

/// The value as a signed integer in `(-p/2, p/2]`, as comparisons read it.
fn balanced(value: &BigUint) -> BigInt {
    let p = modulus();
    if *value > (&p >> 1_u32) {
        BigInt::from(value.clone()) - BigInt::from(p)
    } else {
        BigInt::from(value.clone())
    }
}

fn inverse(value: &BigUint) -> BigUint {
    let p = modulus();
    value.modpow(&(&p - 2_u32), &p)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Failure {
    DivisionByZero,
    InvalidShift,
}

fn oracle(operation: Operation, a: &BigUint, b: &BigUint) -> Result<BigUint, Failure> {
    use Operation::*;
    let p = modulus();
    let zero = BigUint::from(0_u32);
    let flag = |condition: bool| BigUint::from(u32::from(condition));
    Ok(match operation {
        Mul | MMul => a * b % &p,
        Add => (a + b) % &p,
        Sub => (a + &p - b) % &p,
        Eq => flag(a == b),
        Neq => flag(a != b),
        Lt => flag(balanced(a) < balanced(b)),
        Gt => flag(balanced(a) > balanced(b)),
        Leq => flag(balanced(a) <= balanced(b)),
        Geq => flag(balanced(a) >= balanced(b)),
        Lor => flag(*a != zero || *b != zero),
        Land => flag(*a != zero && *b != zero),
        Shl | Shr => {
            if *b >= BigUint::from(256_u32) {
                return Err(Failure::InvalidShift);
            }
            let shift = b.to_u32_digits().first().copied().unwrap_or(0);
            if operation == Shl {
                ((a << shift) % BigUint::from(2_u32).pow(254)) % &p
            } else {
                (a >> shift) % &p
            }
        }
        Band => (a & b) % &p,
        Bor => (a | b) % &p,
        Bxor => (a ^ b) % &p,
        Neg => (&p - a) % &p,
        Inv if *a == zero => return Err(Failure::DivisionByZero),
        Inv => inverse(a),
        Div | Mod | IDiv if *b == zero => return Err(Failure::DivisionByZero),
        Div => a * inverse(b) % &p,
        Mod => a % b,
        IDiv => a / b,
        Pow => a.modpow(b, &p),
    })
}

struct OracleCase {
    graph: Graph,
    inputs: Vec<BigUint>,
    /// The output values, or the first failure and the node it happens at.
    expected: Result<Vec<BigUint>, (Failure, usize)>,
}

/// A graph over one input array `x`, with the value of every node alongside.
fn oracle_case(rng: &mut Rng, max_nodes: usize) -> OracleCase {
    let width = 1 + rng.below(6);
    let inputs = (0..width).map(|_| edge_value(rng)).collect::<Vec<_>>();
    let mut buffer = vec![BigUint::from(1_u32)];
    buffer.extend(inputs.iter().cloned());

    let mut nodes = vec![Node::Constant(U256::from(1_u64))];
    let mut values = vec![BigUint::from(1_u32)];
    let mut failure = None;
    let count = 2 + rng.below(max_nodes);
    while nodes.len() < count {
        let index = nodes.len();
        let prior = |rng: &mut Rng| rng.below(index);
        match rng.below(10) {
            0 | 1 => {
                let input = rng.below(width + 1);
                nodes.push(Node::Input(input));
                values.push(buffer[input].clone());
            }
            2 => {
                let value = edge_value(rng);
                nodes.push(Node::Constant(to_u256(&value)));
                values.push(value);
            }
            3 => {
                let value = edge_value(rng);
                nodes.push(Node::MontConstant(Fr::from_le_bytes_mod_order(
                    &value.to_bytes_le(),
                )));
                values.push(value);
            }
            4 => {
                // The exporter keeps the first argument of a `bbf_inv`; give it two.
                let source = prior(rng);
                nodes.push(Node::Bbf(
                    format!("bbf_inv_{}", rng.below(99)),
                    vec![source, prior(rng)],
                ));
                values.push(if values[source] == BigUint::from(0_u32) {
                    BigUint::from(0_u32)
                } else {
                    inverse(&values[source])
                });
            }
            _ => {
                let operation = ALL_OPERATIONS[rng.below(ALL_OPERATIONS.len())];
                let mut left = prior(rng);
                let mut right = match rng.below(6) {
                    0 => 0,
                    1 => left,
                    _ => prior(rng),
                };
                // Retry operands a few times so most graphs evaluate to the end.
                let mut value = oracle(operation, &values[left], &values[right]);
                for _ in 0..8 {
                    if value.is_ok() || rng.below(25) == 0 {
                        break;
                    }
                    left = prior(rng);
                    right = prior(rng);
                    value = oracle(operation, &values[left], &values[right]);
                }
                let value = value.unwrap_or_else(|reason| {
                    failure.get_or_insert((reason, index));
                    BigUint::from(0_u32)
                });
                nodes.push(Node::Op(operation, left, right));
                values.push(value);
            }
        }
    }

    let mut signals = vec![0];
    for _ in 0..rng.below(count + 2) {
        signals.push(if rng.below(3) == 0 {
            count - 1 - rng.below(count.min(4))
        } else {
            rng.below(count)
        });
    }
    let expected = match failure {
        Some(failure) => Err(failure),
        None => Ok(signals.iter().map(|&s| values[s].clone()).collect()),
    };
    OracleCase {
        graph: Graph {
            nodes,
            signals,
            input_mapping: vec![
                InputMapping {
                    hash: 0,
                    signal_id: 0,
                    signal_size: 1,
                },
                InputMapping {
                    hash: fnv1a("x"),
                    signal_id: 1,
                    signal_size: width as u64,
                },
            ],
        },
        inputs,
        expected,
    }
}

/// Every encoding through every evaluator path, against the oracle. Returns
/// whether the case evaluated to the end.
fn check_oracle(case: &OracleCase, workspace: &mut WitnessWorkspace, label: &str) -> bool {
    let limits = Limits::batch_prover();
    let values = case
        .inputs
        .iter()
        .map(|v| format!("\"{v}\""))
        .collect::<Vec<_>>();
    let input = format!("{{\"x\":[{}]}}", values.join(","));
    let debug = |error: curvy_witness::WitnessError| format!("{error:?}");

    let mut outcomes = Vec::new();
    let mut programs = Vec::new();
    for version in [FormatVersion::V1, FormatVersion::V2] {
        for envelope in [Envelope::Cvywit, Envelope::Signet] {
            let bytes = encode(&case.graph, [9; 32], envelope, version).expect("encode");
            let digest = pin(&bytes);
            let graph =
                WitnessGraph::from_bytes_with_limits(&bytes, &digest, limits).expect("load");
            let sage =
                SageGraph::from_bytes_with_limits(&bytes, &digest, limits).expect("load SAGE");
            let program = sage.to_compiled_bytes().expect("compile SAGE");
            let compiled = SageGraph::from_compiled_bytes_with_limits(
                &program,
                &pin(&program),
                &digest,
                limits,
            )
            .expect("load the compiled SAGE program");
            let path = format!("{version:?}/{envelope:?}");
            outcomes.push((
                format!("{path} default"),
                graph.calculate_json(&input).map_err(debug),
            ));
            outcomes.push((
                format!("{path} default, reused workspace"),
                graph
                    .with_witness_json(&input, workspace, |a| a.to_vec())
                    .map_err(debug),
            ));
            outcomes.push((
                format!("{path} SAGE"),
                sage.calculate_json(&input).map_err(debug),
            ));
            outcomes.push((
                format!("{path} SAGE, reused workspace"),
                sage.with_witness_json(&input, workspace, |a| a.to_vec())
                    .map_err(debug),
            ));
            outcomes.push((
                format!("{path} compiled SAGE"),
                compiled.calculate_json(&input).map_err(debug),
            ));
            programs.push(program);
        }
    }

    // A compiled program names the artifact it came from (bytes 16..48) and is
    // otherwise the same for every encoding of one graph.
    for program in &programs[1..] {
        assert_eq!(program[..16], programs[0][..16], "{label}: program header");
        assert_eq!(program[48..], programs[0][48..], "{label}: program body");
    }
    let (first_path, first) = &outcomes[0];
    for (path, outcome) in &outcomes[1..] {
        assert_eq!(outcome, first, "{label}: {path} differs from {first_path}");
    }
    match (&case.expected, first) {
        (Ok(expected), Ok(assignment)) => {
            let assignment = assignment
                .iter()
                .map(|value| BigUint::from_bytes_le(&value.into_bigint().to_bytes_le()))
                .collect::<Vec<_>>();
            assert_eq!(
                &assignment, expected,
                "{label}: the evaluators disagree with the oracle"
            );
            true
        }
        (Err((failure, node)), Err(error)) => {
            let expected = match failure {
                Failure::DivisionByZero => format!("DivisionByZero({node})"),
                Failure::InvalidShift => format!("InvalidShift({node})"),
            };
            assert_eq!(error, &expected, "{label}: failure");
            false
        }
        (expected, outcome) => panic!(
            "{label}: the oracle expects {:?}, the evaluators returned {:?}",
            expected.as_ref().map(|_| "values"),
            outcome.as_ref().map(|_| "values"),
        ),
    }
}

#[test]
fn every_encoding_and_evaluator_matches_an_independent_oracle() {
    // One workspace for every case, so values left over from a larger graph or a
    // failed evaluation would surface as a mismatch.
    let mut workspace = WitnessWorkspace::new(1 << 20);
    let mut completed = 0;
    for seed in 0..1_500_u64 {
        let mut rng = Rng(seed ^ 0x5EED_0000);
        let case = oracle_case(&mut rng, 60);
        completed += usize::from(check_oracle(&case, &mut workspace, &format!("seed {seed}")));
    }
    assert!(
        completed > 1_200,
        "only {completed} of 1,500 cases evaluated to the end"
    );
}
