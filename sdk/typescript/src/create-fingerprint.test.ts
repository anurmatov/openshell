// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { clearField, fromBinary, fromJson, toBinary, toJson } from '@bufbuild/protobuf';
import { describe, expect, it } from 'vitest';
import { createOwnershipKeyFromRequest } from './create-fingerprint.js';
import { canonicalJSON, createCanonicalRegistry } from './internal/create-canonical.js';

const manifest: {
  fingerprint_schema_digest: string;
  vectors: {
    name: string;
    message_type: string;
    input: Parameters<typeof fromJson>[1];
    unknown_wire_hex: string;
    canonical: string;
    sha256: string;
  }[];
  number_vectors: { ieee754_hex: string; canonical: string }[];
} = JSON.parse(readFileSync(new URL('../../../proto/create_fingerprint.v1.json', import.meta.url), 'utf8'));
const descriptor = readFileSync(new URL('./create_descriptor.bin', import.meta.url));
const registry = createCanonicalRegistry(descriptor);
const requestID = '11111111-1111-4111-8111-111111111111';
const digest = (data: string | Uint8Array) => createHash('sha256').update(data).digest('hex');

describe('canonical Create source vectors', () => {
  it('uses the exact canonical compiled descriptor asset', () => {
    expect(digest(descriptor)).toBe(manifest.fingerprint_schema_digest);
  });
  for (const vector of manifest.vectors) {
    it(vector.name, () => {
      const type = registry.getMessage(vector.message_type);
      if (!type) throw new Error('source vector descriptor missing');
      const message = fromJson(type, vector.input);
      const wire = Buffer.concat([toBinary(type, message), Buffer.from(vector.unknown_wire_hex, 'hex')]);
      const parsed = fromBinary(type, wire);
      if (type.typeName === 'openshell.v1.CreateSandboxRequest') {
        Reflect.set(parsed, 'requestId', requestID);
        const original = toBinary(type, parsed);
        const untouched = Buffer.from(original);
        const key = createOwnershipKeyFromRequest(original, manifest.fingerprint_schema_digest);
        expect(Buffer.from(key.fingerprint).toString('hex')).toBe(vector.sha256);
        expect(Buffer.from(original)).toEqual(untouched);
        const field = type.fields.find((item) => item.name === 'request_id');
        if (!field) throw new Error('source vector request ID field missing');
        clearField(parsed, field);
      }
      const canonical = canonicalJSON(toJson(type, parsed));
      expect(canonical).toBe(vector.canonical);
      expect(digest(canonical)).toBe(vector.sha256);
    });
  }
  for (const vector of manifest.number_vectors) {
    it(`finite number ${vector.ieee754_hex}`, () => {
      const schema = registry.getMessage('openshell.v1.CreateSandboxRequest');
      if (!schema) throw new Error('source vector descriptor missing');
      const number = Buffer.from(vector.ieee754_hex, 'hex').readDoubleBE();
      const message = fromJson(schema, { requestId: requestID, spec: { template: { resources: { n: number } } } });
      const key = createOwnershipKeyFromRequest(toBinary(schema, message), manifest.fingerprint_schema_digest);
      expect(Buffer.from(key.fingerprint).toString('hex')).toBe(
        digest(`{"spec":{"template":{"resources":{"n":${vector.canonical}}}}}`),
      );
    });
  }
  it('refuses malformed, mismatched, oversized, nonfinite and invalid Unicode input', () => {
    for (const wire of [new Uint8Array(), new Uint8Array([255]), new Uint8Array(4 * 1024 * 1024 + 1)]) {
      expect(() => createOwnershipKeyFromRequest(wire, manifest.fingerprint_schema_digest)).toThrow(
        'canonical Create fingerprint unavailable or schema mismatch',
      );
    }
    for (const number of [NaN, Infinity, -Infinity]) expect(() => canonicalJSON(number)).toThrow();
    for (const value of ['\ud800', '\udc00', { '\ud800': 1 }]) expect(() => canonicalJSON(value)).toThrow();
  });
});
