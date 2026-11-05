//! The decoder's limits at their boundaries, in both body versions and both
//! evaluators: the evaluation-cost budget, the input-range rule, the client node
//! count, and the encoder's refusal of constants it could only write unloadably.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use curvy_signet::postcard::{Graph, InputMapping, Node, Operation};
use curvy_signet::{Envelope, FormatVersion, SignetError, encode, hex};
use curvy_witness::sage::SageGraph;
use curvy_witness::{Limits, WitnessError, WitnessGraph};
use ruint::aliases::U256;
use sha2::{Digest, Sha256};

const VERSIONS: [FormatVersion; 2] = [FormatVersion::V1, FormatVersion::V2];

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF2_9CE4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01B3)
    })
}

fn modulus() -> U256 {
    U256::from_limbs(Fr::MODULUS.0)
}

fn input(name: &str, signal_id: u64, signal_size: u64) -> InputMapping {
    InputMapping {
        hash: fnv1a(name),
        signal_id,
        signal_size,
    }
}

fn graph(nodes: Vec<Node>, input_mapping: Vec<InputMapping>) -> Graph {
    Graph {
        nodes,
        signals: vec![0],
        input_mapping,
    }
}

fn artifact(graph: &Graph, version: FormatVersion) -> (Vec<u8>, String) {
    let bytes = encode(graph, [3; 32], Envelope::Signet, version).expect("encode");
    let pin = hex(&Sha256::digest(&bytes));
    (bytes, pin)
}

/// Both evaluators' verdicts, which must agree.
fn load(bytes: &[u8], pin: &str, limits: Limits) -> Result<(), String> {
    let graph = WitnessGraph::from_bytes_with_limits(bytes, pin, limits).map(|_| ());
    let sage = SageGraph::from_bytes_with_limits(bytes, pin, limits).map(|_| ());
    let (graph, sage) = (
        graph.map_err(|e| format!("{e:?}")),
        sage.map_err(|e| format!("{e:?}")),
    );
    assert_eq!(graph, sage, "the evaluators disagree");
    graph
}

/// `count` exponentiations of two near-modulus constants: 3 + 768 * count units.
fn exponentiations(count: usize) -> Graph {
    let mut nodes = vec![
        Node::Constant(U256::from(1_u64)),
        Node::Constant(modulus() - U256::from(12_345_u64)),
        Node::Constant((modulus() >> 1) + U256::from(987_654_321_u64)),
    ];
    nodes.extend((0..count).map(|_| Node::Op(Operation::Pow, 1, 2)));
    graph(nodes, vec![input("a", 1, 1)])
}

#[test]
fn the_evaluation_cost_budget_is_exact_and_checked_before_evaluating() {
    let client = Limits::client();
    assert_eq!(client.evaluation_cost, 32_000_000);
    // 3 + 768 * 41,666 = 31,999,491 fits; one more exponentiation does not.
    let within = exponentiations(41_666);
    let beyond = exponentiations(41_667);
    let refused = format!(
        "EvaluationCostLimit {{ maximum: {} }}",
        client.evaluation_cost
    );
    for version in VERSIONS {
        let (bytes, pin) = artifact(&within, version);
        assert_eq!(
            load(&bytes, &pin, client),
            Ok(()),
            "{version:?}: within the budget"
        );
        let (bytes, pin) = artifact(&beyond, version);
        assert_eq!(
            load(&bytes, &pin, client),
            Err(refused.clone()),
            "{version:?}: beyond it"
        );
        assert_eq!(
            load(&bytes, &pin, Limits::batch_prover()),
            Ok(()),
            "{version:?}: batch prover"
        );
    }
}

#[test]
fn a_compiled_sage_program_is_held_to_the_same_budget() {
    let (bytes, pin) = artifact(&exponentiations(1_000), FormatVersion::V2);
    let program = SageGraph::from_bytes(&bytes, &pin)
        .expect("compile")
        .to_compiled_bytes()
        .expect("encode the program");
    let program_pin = hex(&Sha256::digest(&program));
    let mut limits = Limits::client();
    limits.evaluation_cost = 3 + 768 * 1_000;
    SageGraph::from_compiled_bytes_with_limits(&program, &program_pin, &pin, limits)
        .expect("the program fits its own cost");
    limits.evaluation_cost -= 1;
    let error = SageGraph::from_compiled_bytes_with_limits(&program, &program_pin, &pin, limits)
        .err()
        .expect("one unit short");
    assert!(
        matches!(error, WitnessError::EvaluationCostLimit { .. }),
        "{error:?}"
    );
}

#[test]
fn the_client_node_limit_holds_for_version_2() {
    let client = Limits::client();
    let at = |count: usize| {
        let mut nodes = vec![Node::Constant(U256::from(1_u64))];
        nodes.extend((1..count).map(|_| Node::Input(1)));
        artifact(&graph(nodes, vec![input("a", 1, 1)]), FormatVersion::V2)
    };
    let (bytes, pin) = at(client.nodes);
    assert_eq!(load(&bytes, &pin, client), Ok(()), "at the limit");
    let (bytes, pin) = at(client.nodes + 1);
    assert_eq!(
        load(&bytes, &pin, client),
        Err(format!(
            "CountLimit {{ section: \"node\", actual: {}, maximum: {} }}",
            client.nodes + 1,
            client.nodes
        )),
        "one past it"
    );
    assert_eq!(
        load(&bytes, &pin, Limits::batch_prover()),
        Ok(()),
        "batch prover"
    );
}

#[test]
fn input_ranges_may_nest_but_not_partially_overlap() {
    let one = vec![Node::Constant(U256::from(1_u64))];
    // A bus input and its fields, as the shipped graphs map them: the whole, each
    // field inside it, and a field mapped under two names.
    let nested = vec![
        input("note", 1, 4),
        input("note.amount", 1, 1),
        input("note.owner", 2, 2),
        input("note.owner.x", 2, 1),
        input("alias", 2, 1),
        input("other", 5, 2),
    ];
    for version in VERSIONS {
        let (bytes, pin) = artifact(&graph(one.clone(), nested.clone()), version);
        assert_eq!(
            load(&bytes, &pin, Limits::client()),
            Ok(()),
            "{version:?}: nested"
        );
    }
    for (label, mappings, offender) in [
        ("straddling", vec![input("a", 1, 2), input("b", 2, 2)], 1),
        (
            "listed outer last",
            vec![input("b", 2, 3), input("a", 1, 2)],
            0,
        ),
        (
            "inside one, across another",
            vec![
                input("outer", 1, 6),
                input("left", 1, 3),
                input("right", 3, 2),
            ],
            2,
        ),
    ] {
        for version in VERSIONS {
            let (bytes, pin) = artifact(&graph(one.clone(), mappings.clone()), version);
            assert_eq!(
                load(&bytes, &pin, Limits::client()),
                Err(format!("InputMappingOverlap {{ index: {offender} }}")),
                "{version:?}: {label}"
            );
        }
    }
}

#[test]
fn the_encoder_refuses_a_constant_at_or_above_the_modulus() {
    for (value, accepted) in [
        (modulus() - U256::from(1_u64), true),
        (modulus(), false),
        (U256::MAX, false),
    ] {
        let nodes = vec![Node::Constant(U256::from(1_u64)), Node::Constant(value)];
        let graph = graph(nodes, vec![input("a", 1, 1)]);
        for version in VERSIONS {
            let result = encode(&graph, [3; 32], Envelope::Signet, version);
            if accepted {
                assert!(result.is_ok(), "{version:?}: p - 1");
            } else {
                assert!(
                    matches!(result, Err(SignetError::NonCanonicalConstant { index: 1 })),
                    "{version:?}: {value}"
                );
            }
        }
    }
}
