// SPDX-License-Identifier: Apache-2.0

//! Descriptor-projected Create fingerprints, separate from legacy replay hashing.
//!
//! This foundation does not enable ownership admission or advertise a capability.
//! Cross-SDK conformance and the durable receipt/fence path remain separate requirements.
//! Callers must not use a partial projection or fall back to the legacy replay hash on refusal.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, FileDescriptor};
use serde_json::Value;

use crate::proto::CreateSandboxRequest;

/// The audited format is versioned independently of the existing mutation replay hash.
pub const FORMAT: &str = "create-payload-json-v1";

static DESCRIPTORS: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(crate::FILE_DESCRIPTOR_SET).expect("compiled protobuf descriptors")
});

/// Opaque failures: never include a raw Create payload, token, path or annotation value.
#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    /// The caller compiled another descriptor closure.
    #[error("create fingerprint schema mismatch")]
    SchemaMismatch,
    /// Projection or serialization was not possible.
    #[error("create fingerprint projection unavailable")]
    Projection,
    /// A JSON number cannot be represented as a finite IEEE 754 double.
    #[error("create fingerprint invalid number")]
    InvalidNumber,
    /// Reject excessive nesting rather than producing a truncated digest.
    #[error("create fingerprint nesting limit")]
    DepthLimit,
    /// The configured cryptographic backend refused the operation.
    #[error("create fingerprint digest unavailable")]
    Digest,
}

/// Export the transitive compiled FileDescriptorSet closure in filename order.
///
/// The release vector manifest must pin these measured bytes after the receipt wire is finalized.
/// No source-file hash or guessed future descriptor digest is substituted here.
pub fn schema_descriptor_set() -> Result<Vec<u8>, FingerprintError> {
    fn collect(
        file: FileDescriptor,
        files: &mut BTreeMap<String, prost_types::FileDescriptorProto>,
    ) {
        if files.contains_key(file.name()) {
            return;
        }
        files.insert(file.name().to_owned(), file.file_descriptor_proto().clone());
        for dependency in file.dependencies() {
            collect(dependency, files);
        }
    }

    let descriptor = DESCRIPTORS
        .get_message_by_name("openshell.v1.CreateSandboxRequest")
        .ok_or(FingerprintError::Projection)?;
    let mut files = BTreeMap::new();
    collect(descriptor.parent_file(), &mut files);
    Ok(prost_types::FileDescriptorSet {
        file: files.into_values().collect(),
    }
    .encode_to_vec())
}

/// Digest the exact compiled projection closure, including descriptor metadata.
pub fn schema_digest() -> Result<[u8; 32], FingerprintError> {
    openshell_crypto::sha256(&schema_descriptor_set()?).map_err(|_| FingerprintError::Digest)
}

/// Project the actual generated request, clearing only request_id before ProtoJSON encoding.
///
/// Unknown binary fields are not serialized by descriptor projection. Presence, int64 strings,
/// bytes, enum names and protobuf defaults are handled by the pinned prost-reflect serializer.
/// The expected schema must be checked before returning any fingerprint bytes.
pub fn canonical_payload(
    request: &CreateSandboxRequest,
    expected_schema: &[u8; 32],
) -> Result<Vec<u8>, FingerprintError> {
    if &schema_digest()? != expected_schema {
        return Err(FingerprintError::SchemaMismatch);
    }
    let descriptor = DESCRIPTORS
        .get_message_by_name("openshell.v1.CreateSandboxRequest")
        .ok_or(FingerprintError::Projection)?;
    let request_id = descriptor
        .get_field_by_name("request_id")
        .ok_or(FingerprintError::Projection)?;
    let mut message = DynamicMessage::decode(descriptor, request.encode_to_vec().as_slice())
        .map_err(|_| FingerprintError::Projection)?;
    message.clear_field(&request_id);
    let value = serde_json::to_value(&message).map_err(|_| FingerprintError::Projection)?;
    let mut output = Vec::new();
    write_canonical(&value, &mut output, 0)?;
    Ok(output)
}

/// Return SHA256 of the exact canonical UTF-8 bytes, without a newline or BOM.
pub fn fingerprint(
    request: &CreateSandboxRequest,
    expected_schema: &[u8; 32],
) -> Result<[u8; 32], FingerprintError> {
    let payload = canonical_payload(request, expected_schema)?;
    openshell_crypto::sha256(&payload).map_err(|_| FingerprintError::Digest)
}

fn write_canonical(
    value: &Value,
    output: &mut Vec<u8>,
    depth: usize,
) -> Result<(), FingerprintError> {
    if depth > 128 {
        return Err(FingerprintError::DepthLimit);
    }
    match value {
        Value::Object(map) => {
            let mut fields: Vec<_> = map.iter().collect();
            fields.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            output.push(b'{');
            for (index, (key, value)) in fields.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|_| FingerprintError::Projection)?;
                output.push(b':');
                write_canonical(value, output, depth + 1)?;
            }
            output.push(b'}');
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(value, output, depth + 1)?;
            }
            output.push(b']');
        }
        Value::Number(number) => {
            let value = number
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or(FingerprintError::InvalidNumber)?;
            let mut buffer = ryu_js::Buffer::new();
            output.extend_from_slice(buffer.format_finite(value).as_bytes());
        }
        _ => serde_json::to_writer(output, value).map_err(|_| FingerprintError::Projection)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_manifest_matches_the_compiled_descriptor() {
        let manifest: Value =
            serde_json::from_str(include_str!("../../../proto/create_fingerprint.v1.json"))
                .unwrap();
        let measured: String = schema_digest()
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            measured,
            manifest["fingerprint_schema_digest"].as_str().unwrap()
        );
        assert_eq!(manifest["format"], FORMAT);
    }

    #[test]
    fn go_canonical_descriptor_is_the_exact_compiled_projection() {
        assert_eq!(
            schema_descriptor_set().unwrap(),
            include_bytes!("../../../sdk/go/openshell/v1/create_descriptor.bin")
        );
    }

    #[test]
    fn typescript_canonical_descriptor_is_the_exact_compiled_projection() {
        assert_eq!(
            schema_descriptor_set().unwrap(),
            include_bytes!("../../../sdk/typescript/src/create_descriptor.bin")
        );
    }

    #[test]
    fn python_canonical_descriptor_is_the_exact_compiled_projection() {
        assert_eq!(
            schema_descriptor_set().unwrap(),
            include_bytes!("../../../python/openshell/create_descriptor.bin")
        );
    }

    #[test]
    fn published_vectors_match_actual_projection_and_hashes() {
        let manifest: Value =
            serde_json::from_str(include_str!("../../../proto/create_fingerprint.v1.json"))
                .unwrap();
        for vector in manifest["vectors"].as_array().unwrap() {
            let name = vector["name"].as_str().unwrap();
            let message_type = vector["message_type"].as_str().unwrap();
            let descriptor = DESCRIPTORS.get_message_by_name(message_type).unwrap();
            let message = DynamicMessage::deserialize(descriptor, vector["input"].clone()).unwrap();
            let mut wire = message.encode_to_vec();
            let unknown = vector["unknown_wire_hex"].as_str().unwrap();
            for index in (0..unknown.len()).step_by(2) {
                wire.push(u8::from_str_radix(&unknown[index..index + 2], 16).unwrap());
            }
            let output = if message_type == "openshell.v1.CreateSandboxRequest" {
                let request = CreateSandboxRequest::decode(wire.as_slice()).unwrap();
                canonical_payload(&request, &schema_digest().unwrap()).unwrap()
            } else {
                let projection = serde_json::to_value(&message).unwrap();
                let mut output = Vec::new();
                write_canonical(&projection, &mut output, 0).unwrap();
                output
            };
            assert_eq!(
                output,
                vector["canonical"].as_str().unwrap().as_bytes(),
                "{name}"
            );
            let digest: String = openshell_crypto::sha256(&output)
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(digest, vector["sha256"].as_str().unwrap(), "{name}");
        }
    }

    #[test]
    fn rfc8785_appendix_b_finite_number_vectors_match() {
        let manifest: Value =
            serde_json::from_str(include_str!("../../../proto/create_fingerprint.v1.json"))
                .unwrap();
        for vector in manifest["number_vectors"].as_array().unwrap() {
            let bits = u64::from_str_radix(vector["ieee754_hex"].as_str().unwrap(), 16).unwrap();
            let number = serde_json::Number::from_f64(f64::from_bits(bits)).unwrap();
            let mut output = Vec::new();
            write_canonical(&Value::Number(number), &mut output, 0).unwrap();
            assert_eq!(output, vector["canonical"].as_str().unwrap().as_bytes());
        }
    }

    #[test]
    fn nesting_over_the_bound_is_refused_without_returning_a_fingerprint() {
        let mut value = Value::Null;
        for _ in 0..129 {
            value = Value::Array(vec![value]);
        }
        assert!(matches!(
            write_canonical(&value, &mut Vec::new(), 0),
            Err(FingerprintError::DepthLimit)
        ));
    }

    #[test]
    fn request_id_is_excluded_and_scalar_defaults_are_omitted() {
        let request = CreateSandboxRequest {
            request_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            ..Default::default()
        };
        let schema = schema_digest().unwrap();
        assert_eq!(canonical_payload(&request, &schema).unwrap(), b"{}");
        assert_eq!(
            fingerprint(&request, &schema).unwrap(),
            openshell_crypto::sha256(b"{}").unwrap()
        );
    }

    #[test]
    fn schema_mismatch_is_refused_before_fingerprinting() {
        let mut wrong = schema_digest().unwrap();
        wrong[0] ^= 1;
        assert!(matches!(
            fingerprint(&CreateSandboxRequest::default(), &wrong),
            Err(FingerprintError::SchemaMismatch)
        ));
    }

    #[test]
    fn present_empty_message_is_not_absent() {
        let schema = schema_digest().unwrap();
        let request = CreateSandboxRequest {
            spec: Some(Default::default()),
            ..Default::default()
        };
        assert_eq!(
            canonical_payload(&request, &schema).unwrap(),
            br#"{"spec":{}}"#
        );
    }

    #[test]
    fn maps_sort_by_utf16_not_utf8_without_normalization() {
        let mut request = CreateSandboxRequest::default();
        request
            .labels
            .insert("\u{e000}".to_owned(), "bmp".to_owned());
        request
            .labels
            .insert("\u{10000}".to_owned(), "supplementary".to_owned());
        let expected = "{\"labels\":{\"\u{10000}\":\"supplementary\",\"\u{e000}\":\"bmp\"}}";
        assert_eq!(
            canonical_payload(&request, &schema_digest().unwrap()).unwrap(),
            expected.as_bytes()
        );
    }

    #[test]
    fn unknown_binary_fields_do_not_change_the_projection() {
        let mut wire = CreateSandboxRequest::default().encode_to_vec();
        wire.extend_from_slice(&[0xa0, 0x06, 0x01]); // Unknown varint field 100.
        let request = CreateSandboxRequest::decode(wire.as_slice()).unwrap();
        assert_eq!(
            canonical_payload(&request, &schema_digest().unwrap()).unwrap(),
            b"{}"
        );
    }

    #[test]
    fn repeated_order_strings_and_integer_values_are_preserved() {
        let value = serde_json::json!({"z": [2, 1], "a": "\n\"\\", "i64": "9223372036854775807"});
        let mut output = Vec::new();
        write_canonical(&value, &mut output, 0).unwrap();
        assert_eq!(
            output,
            br#"{"a":"\n\"\\","i64":"9223372036854775807","z":[2,1]}"#
        );
    }

    #[test]
    fn finite_floats_follow_ecmascript_spelling() {
        for (input, expected) in [
            (-0.0, "0"),
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (333333333.33333329, "333333333.3333333"),
            (f64::from_bits(1), "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
        ] {
            let mut output = Vec::new();
            write_canonical(&serde_json::json!(input), &mut output, 0).unwrap();
            assert_eq!(output, expected.as_bytes());
        }
    }
}

#[cfg(test)]
mod ownership_wire_tests {
    use super::*;

    #[test]
    fn create_receipt_wire_preserves_additive_field_numbers_and_authority_boundaries() {
        let request = CreateSandboxRequest {
            require_ownership_receipt: true,
            ..Default::default()
        };
        let message = DESCRIPTORS
            .get_message_by_name("openshell.v1.CreateSandboxRequest")
            .unwrap();
        assert_eq!(
            message
                .get_field_by_name("require_ownership_receipt")
                .unwrap()
                .number(),
            10
        );
        assert!(
            canonical_payload(&request, &schema_digest().unwrap())
                .unwrap()
                .windows(b"requireOwnershipReceipt".len())
                .any(|part| part == b"requireOwnershipReceipt")
        );
        let lookup = crate::proto::GetSandboxCreateReceiptRequest {
            expected_sandbox_id: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(lookup.expected_sandbox_id, Some(String::new()));
        let response = DESCRIPTORS
            .get_message_by_name("openshell.v1.GetSandboxCreateReceiptResponse")
            .unwrap();
        for (name, number) in [
            ("receipt_state", 1),
            ("fingerprint", 3),
            ("bindings", 9),
            ("complete", 10),
            ("fingerprint_schema_digest", 11),
            ("fence_revision", 12),
            ("admission_closed", 13),
            ("reason_code", 14),
        ] {
            assert_eq!(response.get_field_by_name(name).unwrap().number(), number);
        }
    }
}
