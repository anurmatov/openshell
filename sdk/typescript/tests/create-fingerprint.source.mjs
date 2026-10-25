// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { clearField, fromBinary, fromJson, toBinary, toJson } from '@bufbuild/protobuf';
import { createOwnershipKeyFromRequest } from '../dist/create-fingerprint.js';
import { canonicalJSON, createCanonicalRegistry } from '../dist/internal/create-canonical.js';

const manifest = JSON.parse(readFileSync(new URL('../../../proto/create_fingerprint.v1.json', import.meta.url)));
const descriptor = readFileSync(new URL('../dist/create_descriptor.bin', import.meta.url));
const registry = createCanonicalRegistry(descriptor);
const schema = registry.getMessage('openshell.v1.CreateSandboxRequest');
const requestID = '11111111-1111-4111-8111-111111111111';
const digest = (data) => createHash('sha256').update(data).digest('hex');

test('compiled descriptor matches the canonical release manifest', () => {
  assert.equal(digest(descriptor), manifest.fingerprint_schema_digest);
});
for (const vector of manifest.vectors) {
  test(`shared projection: ${vector.name}`, () => {
    const type = registry.getMessage(vector.message_type);
    const message = fromJson(type, vector.input);
    const original = Buffer.concat([toBinary(type, message), Buffer.from(vector.unknown_wire_hex, 'hex')]);
    const parsed = fromBinary(type, original);
    if (vector.message_type === schema.typeName) {
      parsed.requestId = requestID;
      const wire = toBinary(type, parsed);
      const untouched = Buffer.from(wire);
      const key = createOwnershipKeyFromRequest(wire, manifest.fingerprint_schema_digest);
      assert.equal(key.requestID, requestID);
      assert.equal(Buffer.from(key.fingerprint).toString('hex'), vector.sha256);
      assert.deepEqual(Buffer.from(wire), untouched);
      clearField(
        parsed,
        type.fields.find((field) => field.name === 'request_id'),
      );
    }
    const canonical = canonicalJSON(toJson(type, parsed));
    assert.equal(canonical, vector.canonical);
    assert.equal(digest(canonical), vector.sha256);
  });
}
for (const vector of manifest.number_vectors) {
  test(`finite number through actual Create: ${vector.ieee754_hex}`, () => {
    const number = Buffer.from(vector.ieee754_hex, 'hex').readDoubleBE();
    const message = fromJson(schema, { requestId: requestID, spec: { template: { resources: { n: number } } } });
    const key = createOwnershipKeyFromRequest(toBinary(schema, message), manifest.fingerprint_schema_digest);
    assert.equal(
      Buffer.from(key.fingerprint).toString('hex'),
      digest(`{"spec":{"template":{"resources":{"n":${vector.canonical}}}}}`),
    );
  });
}
test('refuse bad schema, UUID, binary, nonfinite, depth and invalid Unicode without payload disclosure', () => {
  const good = toBinary(schema, fromJson(schema, { requestId: requestID }));
  const error = { message: 'canonical Create fingerprint unavailable or schema mismatch' };
  for (const wire of [new Uint8Array(), new Uint8Array([255]), new Uint8Array(4 * 1024 * 1024 + 1)]) {
    assert.throws(() => createOwnershipKeyFromRequest(wire, manifest.fingerprint_schema_digest), error);
  }
  assert.throws(() => createOwnershipKeyFromRequest(good, '0'.repeat(64)), error);
  for (const requestId of ['', '00000000-0000-0000-0000-000000000000', 'not-a-uuid']) {
    const wire = toBinary(schema, fromJson(schema, { requestId }));
    assert.throws(() => createOwnershipKeyFromRequest(wire, manifest.fingerprint_schema_digest), error);
  }
  for (const number of [NaN, Infinity, -Infinity]) {
    assert.throws(() => canonicalJSON(number));
    const message = fromJson(schema, { requestId: requestID, spec: { template: { resources: { n: 0 } } } });
    message.spec.template.resources.n = number;
    assert.throws(
      () => createOwnershipKeyFromRequest(toBinary(schema, message), manifest.fingerprint_schema_digest),
      error,
    );
  }
  for (const value of ['\ud800', '\udc00', { '\ud800': 1 }]) {
    assert.throws(() => canonicalJSON(value));
  }
  let deep = null;
  for (let i = 0; i < 130; i++) deep = [deep];
  assert.throws(() => canonicalJSON(deep));
  assert.equal(
    canonicalJSON({ '\ue000': 'bmp', '\u{10000}': '\u2028\u2029<>&\x00' }),
    '{"\u{10000}":"\u2028\u2029<>&\\u0000","\ue000":"bmp"}',
  );
  assert.equal(canonicalJSON({ 2: 'two', 10: 'ten' }), '{"10":"ten","2":"two"}');
});
test('retain audited flag, exclude only request ID and return independent key bytes', () => {
  const key = (input) =>
    createOwnershipKeyFromRequest(toBinary(schema, fromJson(schema, input)), manifest.fingerprint_schema_digest);
  const first = key({ requestId: requestID, requireOwnershipReceipt: true });
  const second = key({ requestId: '22222222-2222-4222-8222-222222222222', requireOwnershipReceipt: true });
  assert.deepEqual(first.fingerprint, second.fingerprint);
  assert.notDeepEqual(first.fingerprint, key({ requestId: requestID }).fingerprint);
  first.fingerprint.fill(255);
  assert.notDeepEqual(first.fingerprint, second.fingerprint);
});
