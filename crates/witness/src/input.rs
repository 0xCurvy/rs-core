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
                *self.failure = Some(WitnessError::UnknownInput(if name.len() <= 128 {
                    name
                } else {
                    "<oversized signal name>".into()
                }));
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
                *self.failure = Some(WitnessError::InputLength {
                    name,
                    expected: mapping.signal_size,
                    actual: count,
                });
                return Err(de::Error::custom("incorrect input length"));
            }
        }
        Ok(())
    }
}
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
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Err(E::custom(
            "use decimal strings for integers outside the JSON integer range",
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
