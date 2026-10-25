// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { clearField, fromBinary, toJson } from '@bufbuild/protobuf';
import { canonicalJSON, createCanonicalRegistry } from './internal/create-canonical.js';

/** Original request ownership, never a same-name replacement or runtime proof. */
export interface CreateOwnershipKey {
  readonly requestID: string;
  readonly fingerprint: Uint8Array;
  readonly schemaDigest: string;
}

/**
 * Project the exact original binary Create with the canonical compiled schema.
 * Clear only request_id on a decoded copy, never the audited flag or caller data.
 * expectedSchemaDigest comes from the same qualified release's vector manifest.
 * This method sends no RPC and has no legacy hash or descriptor fallback.
 */
export function createOwnershipKeyFromRequest(
  originalWire: Uint8Array,
  expectedSchemaDigest: string,
): CreateOwnershipKey {
  try {
    if (originalWire.byteLength > 4 * 1024 * 1024) throw new Error();
    const descriptor = readFileSync(new URL('./create_descriptor.bin', import.meta.url));
    const schemaDigest = createHash('sha256').update(descriptor).digest('hex');
    if (expectedSchemaDigest !== schemaDigest) throw new Error();
    const registry = createCanonicalRegistry(descriptor);
    const schema = registry.getMessage('openshell.v1.CreateSandboxRequest');
    if (!schema) throw new Error();
    const message = fromBinary(schema, originalWire, { recursionLimit: 128 });
    const requestIDField = schema.fields.find((field) => field.name === 'request_id');
    if (!requestIDField) throw new Error();
    const requestID: unknown = (message as unknown as Record<string, unknown>)[requestIDField.localName];
    if (
      typeof requestID !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(requestID) ||
      requestID === '00000000-0000-0000-0000-000000000000'
    ) {
      throw new Error();
    }
    clearField(message, requestIDField);
    const canonical = canonicalJSON(toJson(schema, message));
    const fingerprint = new Uint8Array(createHash('sha256').update(canonical, 'utf8').digest());
    return { requestID, fingerprint, schemaDigest };
  } catch {
    // Do not expose protobuf parse errors, request values, paths or credentials.
    throw new TypeError('canonical Create fingerprint unavailable or schema mismatch');
  }
}
