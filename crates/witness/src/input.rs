//! Streaming circuit-input decoding: no JSON DOM, duplicate keys, or value echo.
use crate::{InputMapping, Limits, WitnessError, fnv1a, reserved_vec};
use ark_bn254::Fr;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;

pub(super) fn build_input_buffer(
    mappings: &[InputMapping],
    length: usize,
    json: &str,
    limits: &Limits,
) -> Result<Vec<Fr>, WitnessError> {
    if json.len() > limits.input_json_bytes {
        return Err(WitnessError::InputTooLarge {
            maximum: limits.input_json_bytes,
        });
    }
    let mut values = zeroize::Zeroizing::new(reserved_vec("input values", length)?);
    values.resize(length, Fr::from(0u64));
    values[0] = Fr::from(1u64);
    let mut matched = vec![false; mappings.len()];
    let mut decoder = serde_json::Deserializer::from_str(json);
    let mut failure = None;
    let result = InputObject {
        mappings,
        values: &mut values,
        matched: &mut matched,
        failure: &mut failure,
    }
    .deserialize(&mut decoder);
    if let Some(error) = failure {
        return Err(error);
    }
    result.map_err(WitnessError::InvalidInputJson)?;
    decoder.end().map_err(WitnessError::InvalidInputJson)?;
    Ok(std::mem::take(&mut *values))
}

struct InputObject<'a> {
    mappings: &'a [InputMapping],
    values: &'a mut [Fr],
    matched: &'a mut [bool],
    failure: &'a mut Option<WitnessError>,
}
impl<'de> DeserializeSeed<'de> for InputObject<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for InputObject<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a circuit input object")
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Err(E::custom("witness input must be an object"))
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Err(E::custom("witness input must be an object"))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Err(E::custom("witness input must be an object"))
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Err(E::custom("witness input must be an object"))
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        while let Some(name) = map.next_key::<String>()? {
            let hash = fnv1a(&name);
            let Some((index, mapping)) = self
                .mappings
                .iter()
                .enumerate()
                .find(|(_, m)| m.hash == hash)
            else {
                *self.failure = Some(WitnessError::UnknownInput(bounded_name(name)));
                return Err(de::Error::custom("unknown input signal"));
            };
            if self.matched[index] {
                return Err(de::Error::custom(
                    "duplicate input signal or signal-name hash collision",
                ));
            }
            self.matched[index] = true;
            let mut count = 0;
            let output =
                &mut self.values[mapping.signal_id..mapping.signal_id + mapping.signal_size];
            map.next_value_seed(Fields {
                output,
                count: &mut count,
            })?;
            if count != mapping.signal_size {
                // The graph stores only name hashes, so this is the caller's key:
                // an FNV-1a collision can match an arbitrarily long one.
                *self.failure = Some(WitnessError::InputLength {
                    name: bounded_name(name),
                    expected: mapping.signal_size,
                    actual: count,
                });
                return Err(de::Error::custom("incorrect input length"));
            }
        }
        Ok(())
    }
}
/// Echo a signal name into an error only while it is plausibly a name.
fn bounded_name(name: String) -> String {
    if name.len() <= MAX_ECHOED_NAME_BYTES {
        name
    } else {
        "<oversized signal name>".into()
    }
}
const MAX_ECHOED_NAME_BYTES: usize = 128;

struct Fields<'a> {
    output: &'a mut [Fr],
    count: &'a mut usize,
}
impl Fields<'_> {
    fn push<E: de::Error>(self, value: Fr) -> Result<(), E> {
        let slot = self
            .output
            .get_mut(*self.count)
            .ok_or_else(|| E::custom("too many input values"))?;
        *slot = value;
        *self.count += 1;
        Ok(())
    }
}
impl<'de> DeserializeSeed<'de> for Fields<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Fields<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("decimal integers or arrays")
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.push(parse_field(value).ok_or_else(|| E::custom("invalid decimal field value"))?)
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<(), E> {
        self.push(Fr::from(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<(), E> {
        let field = Fr::from(value.unsigned_abs());
        self.push(if value < 0 { -field } else { field })
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<(), E> {
        // serde_json has no negative-zero integer, so the literal `-0` arrives
        // here as -0.0. Zero is exact in any representation; every other float
        // is a fraction, an exponent, or an integer that lost precision.
        if value == 0.0 {
            return self.push(Fr::from(0u64));
        }
        Err(E::custom(
            "JSON numbers must be integers in the 64-bit range without a fraction \
             or exponent; use decimal strings for larger integers",
        ))
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Err(E::custom("unsupported input value"))
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Err(E::custom("unsupported input value"))
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<(), S::Error> {
        while seq
            .next_element_seed(Fields {
                output: self.output,
                count: self.count,
            })?
            .is_some()
        {}
        Ok(())
    }
}
fn parse_field(value: &str) -> Option<Fr> {
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |d| (true, d));
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let radix = Fr::from(10_000_000_000_000_000_000u64);
    let mut field = Fr::from(0u64);
    for chunk in digits.as_bytes().chunks(19) {
        let word = chunk.iter().fold(0u64, |n, b| n * 10 + u64::from(b - b'0'));
        let scale = if chunk.len() == 19 {
            radix
        } else {
            Fr::from(10u64.pow(chunk.len() as u32))
        };
        field = field * scale + Fr::from(word);
    }
    Some(if negative { -field } else { field })
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use num_bigint::BigUint;
    #[test]
    fn input_decoding_rejects_duplicates_overflow_and_redacts_values() {
        let mapping = [InputMapping {
            hash: fnv1a("a"),
            signal_id: 1,
            signal_size: 1,
        }];
        let limits = Limits::client();
        for json in [
            r#"{"a":"PRIVATE_SENTINEL!"}"#,
            r#"{"a":[["PRIVATE_SENTINEL!"]]}"#,
            r#"{"a":[1,2]}"#,
            r#"{"a":1,"a":2}"#,
            r#"{"a":1e21}"#,
            r#""PRIVATE_SENTINEL!""#,
        ] {
            let error = build_input_buffer(&mapping, 2, json, &limits).unwrap_err();
            assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
        }
        assert_eq!(
            build_input_buffer(&mapping, 2, r#"{"a":[[-3]]}"#, &limits).unwrap(),
            vec![Fr::from(1u64), -Fr::from(3u64)]
        );
    }

    #[test]
    fn json_integer_literals_cover_the_64_bit_range_including_negative_zero() {
        let mapping = [InputMapping {
            hash: fnv1a("a"),
            signal_id: 1,
            signal_size: 1,
        }];
        let limits = Limits::client();
        let decode = |json: &str| build_input_buffer(&mapping, 2, json, &limits).map(|v| v[1]);
        for zero in [r#"{"a":-0}"#, r#"{"a":[-0]}"#, r#"{"a":0}"#] {
            assert_eq!(decode(zero).unwrap(), Fr::from(0u64), "{zero}");
        }
        assert_eq!(
            decode(r#"{"a":18446744073709551615}"#).unwrap(),
            Fr::from(u64::MAX)
        );
        assert_eq!(
            decode(r#"{"a":-9223372036854775808}"#).unwrap(),
            -Fr::from(1u64 << 63)
        );
        for rejected in [
            r#"{"a":1.5}"#,
            r#"{"a":1e2}"#,
            r#"{"a":18446744073709551616}"#,
            r#"{"a":-9223372036854775809}"#,
        ] {
            let error = decode(rejected).unwrap_err().to_string();
            assert!(error.contains("without a fraction or exponent"), "{error}");
        }
    }

    #[test]
    fn length_errors_redact_oversized_keys_matched_by_hash() {
        // A long key only reaches a mapping through an FNV-1a collision; model
        // that by pinning the mapping to the long key's own hash.
        let long = format!("PRIVATE_SENTINEL{}", "x".repeat(128));
        let mapping = [InputMapping {
            hash: fnv1a(&long),
            signal_id: 1,
            signal_size: 2,
        }];
        let json = format!(r#"{{"{long}":1}}"#);
        let error = build_input_buffer(&mapping, 3, &json, &Limits::client()).unwrap_err();
        assert!(
            matches!(&error, WitnessError::InputLength { name, expected: 2, actual: 1 }
                if name == "<oversized signal name>"),
            "{error:?}"
        );
        assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
        let short = [InputMapping {
            hash: fnv1a("a"),
            ..mapping[0]
        }];
        assert!(matches!(
            build_input_buffer(&short, 3, r#"{"a":1}"#, &Limits::client()),
            Err(WitnessError::InputLength { name, .. }) if name == "a"
        ));
    }

    #[test]
    fn decimal_parser_matches_independent_bigint_reduction() {
        for len in [1, 18, 19, 20, 38, 77, 512, 4096] {
            let text: String = (0..len)
                .map(|i| char::from(b'0' + ((i * 7 + 3) % 10) as u8))
                .collect();
            let n = BigUint::parse_bytes(text.as_bytes(), 10).unwrap();
            let expected = Fr::from_le_bytes_mod_order(&n.to_bytes_le());
            assert_eq!(parse_field(&text), Some(expected));
            assert_eq!(parse_field(&format!("-{text}")), Some(-expected));
        }
        for value in ["", "-", "1e21", "secret123!", "1_000"] {
            assert_eq!(parse_field(value), None);
        }
    }
}
