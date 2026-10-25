# SPDX-License-Identifier: Apache-2.0

"""Canonical source oracle, also runnable without unrelated SDK HTTP dependencies."""

import hashlib
import importlib.util
import json
import math
import struct
import sys
import tomllib
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from google.protobuf import json_format, message_factory

# Load the actual self-contained production module, not a duplicate projector.
# This does not test package-root imports, channels, HTTP auth or receipt RPCs.
SOURCE = Path(__file__).with_name("create_fingerprint.py")
SPEC = importlib.util.spec_from_file_location("_create_fingerprint_source", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("canonical source module unavailable")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
MANIFEST = json.loads(
    (Path(__file__).parents[2] / "proto/create_fingerprint.v1.json").read_text()
)
DIGEST = MANIFEST["fingerprint_schema_digest"]
REQUEST_ID = "11111111-1111-4111-8111-111111111111"


class CreateFingerprintSourceTests(unittest.TestCase):
    def test_descriptor_matches_canonical_release(self):
        self.assertEqual(
            hashlib.sha256(
                SOURCE.with_name("create_descriptor.bin").read_bytes()
            ).hexdigest(),
            DIGEST,
        )

    def test_refusal_and_immutable_independent_keys(self):
        pool = MODULE._descriptor_pool()
        cls = message_factory.GetMessageClass(
            pool.FindMessageTypeByName("openshell.v1.CreateSandboxRequest")
        )
        good = cls(request_id=REQUEST_ID, require_ownership_receipt=True)
        wire = bytearray(good.SerializeToString())
        key = MODULE.create_ownership_key_from_request(wire, DIGEST)
        self.assertEqual(key.request_id, REQUEST_ID)
        self.assertIsInstance(key.fingerprint, bytes)
        with self.assertRaises(FrozenInstanceError):
            setattr(key, "schema_digest", "changed")
        other = cls.FromString(wire)
        other.request_id = "22222222-2222-4222-8222-222222222222"
        self.assertEqual(
            key.fingerprint,
            MODULE.create_ownership_key_from_request(
                other.SerializeToString(), DIGEST
            ).fingerprint,
        )
        good.require_ownership_receipt = False
        self.assertNotEqual(
            key.fingerprint,
            MODULE.create_ownership_key_from_request(
                good.SerializeToString(), DIGEST
            ).fingerprint,
        )
        wire[:] = b"changed"
        self.assertEqual(len(key.fingerprint), 32)
        for bad in [b"", b"\xff", bytes(4 * 1024 * 1024 + 1)]:
            with self.assertRaisesRegex(
                ValueError,
                "canonical Create fingerprint unavailable or schema mismatch",
            ):
                MODULE.create_ownership_key_from_request(bad, DIGEST)
        with self.assertRaises(ValueError):
            MODULE.create_ownership_key_from_request(
                other.SerializeToString(), "0" * 64
            )
        for bad_id in ["", "not-a-uuid", "00000000-0000-0000-0000-000000000000"]:
            with self.assertRaises(ValueError):
                MODULE.create_ownership_key_from_request(
                    cls(request_id=bad_id).SerializeToString(), DIGEST
                )
        for number in [math.nan, math.inf, -math.inf]:
            with self.assertRaises(ValueError):
                MODULE._canonical_json(number)
            request = cls(request_id=REQUEST_ID)
            request.spec.template.resources.fields["n"].number_value = number
            with self.assertRaises(ValueError):
                MODULE.create_ownership_key_from_request(
                    request.SerializeToString(), DIGEST
                )

    def test_unicode_order_depth_and_package_asset_declaration(self):
        self.assertEqual(
            MODULE._canonical_json(
                {"\ue000": "bmp", "\U00010000": "\u2028\u2029<>&\x00"}
            ),
            '{"\U00010000":"\u2028\u2029<>&\\u0000","\ue000":"bmp"}',
        )
        for bad in ["\ud800", "\udc00", {"\ud800": 1}]:
            with self.assertRaises(ValueError):
                MODULE._canonical_json(bad)
        deep = None
        for _ in range(130):
            deep = [deep]
        with self.assertRaises(ValueError):
            MODULE._canonical_json(deep)
        project = tomllib.loads(
            (Path(__file__).parents[2] / "pyproject.toml").read_text()
        )
        self.assertIn(
            "create_descriptor.bin",
            project["tool"]["setuptools"]["package-data"]["openshell"],
        )


def vector_test(vector):
    def test(self):
        pool = MODULE._descriptor_pool()
        cls = message_factory.GetMessageClass(
            pool.FindMessageTypeByName(vector["message_type"])
        )
        message = json_format.ParseDict(vector["input"], cls(), descriptor_pool=pool)
        message.ParseFromString(
            message.SerializeToString() + bytes.fromhex(vector["unknown_wire_hex"])
        )
        if vector["message_type"] == "openshell.v1.CreateSandboxRequest":
            message.request_id = REQUEST_ID
            original = message.SerializeToString()
            key = MODULE.create_ownership_key_from_request(original, DIGEST)
            self.assertEqual(key.fingerprint.hex(), vector["sha256"])
            self.assertEqual(message.SerializeToString(), original)
            message.ClearField("request_id")
        canonical = MODULE._canonical_json(
            json_format.MessageToDict(message, descriptor_pool=pool)
        )
        self.assertEqual(canonical, vector["canonical"])
        self.assertEqual(
            hashlib.sha256(canonical.encode()).hexdigest(), vector["sha256"]
        )

    return test


def number_test(vector):
    def test(self):
        number = struct.unpack(">d", bytes.fromhex(vector["ieee754_hex"]))[0]
        pool = MODULE._descriptor_pool()
        cls = message_factory.GetMessageClass(
            pool.FindMessageTypeByName("openshell.v1.CreateSandboxRequest")
        )
        message = cls(request_id=REQUEST_ID)
        message.spec.template.resources.fields["n"].number_value = number
        key = MODULE.create_ownership_key_from_request(
            message.SerializeToString(), DIGEST
        )
        expected = (
            '{"spec":{"template":{"resources":{"n":'
            + vector["canonical"]
            + '}}}}'
        )
        self.assertEqual(
            key.fingerprint.hex(), hashlib.sha256(expected.encode()).hexdigest()
        )

    return test


for index, vector in enumerate(MANIFEST["vectors"]):
    setattr(
        CreateFingerprintSourceTests,
        f"test_vector_{index:02d}_{vector['name'].replace('-', '_')}",
        vector_test(vector),
    )
for vector in MANIFEST["number_vectors"]:
    setattr(
        CreateFingerprintSourceTests,
        f"test_number_{vector['ieee754_hex']}",
        number_test(vector),
    )

if __name__ == "__main__":
    unittest.main(verbosity=2)
