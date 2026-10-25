// SPDX-License-Identifier: Apache-2.0

import { createFileRegistry, fromBinary } from '@bufbuild/protobuf';
import { FileDescriptorSetSchema } from '@bufbuild/protobuf/wkt';

export function createCanonicalRegistry(descriptor: Uint8Array) {
  const set = fromBinary(FileDescriptorSetSchema, descriptor);
  const files = new Map(set.file.map((file) => [file.name, file]));
  // The canonical wire closure is filename-sorted, not topologically ordered.
  // Resolve its original files without rewriting the bytes used by the digest.
  const ordered: typeof set.file = [];
  const visited = new Set<string>();
  const active = new Set<string>();
  function visit(name: string) {
    if (visited.has(name)) return;
    const file = files.get(name);
    if (!file || active.has(name)) throw new TypeError('canonical Create descriptor unavailable');
    active.add(name);
    for (const dependency of file.dependency) visit(dependency);
    active.delete(name);
    visited.add(name);
    ordered.push(file);
  }
  visit('openshell.proto');
  return createFileRegistry({ ...set, file: ordered });
}

// Internal shared writer for descriptor-projected ProtoJSON, never a replacement
// for projection or a hash of arbitrary request objects.
export function canonicalJSON(value: unknown, depth = 0): string {
  if (depth > 128) throw new TypeError('canonical JSON nesting limit');
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('canonical JSON requires finite numbers');
      return JSON.stringify(value);
    case 'string':
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code >= 0xd800 && code <= 0xdbff) {
          const next = value.charCodeAt(++i);
          if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('canonical JSON invalid Unicode');
        } else if (code >= 0xdc00 && code <= 0xdfff) {
          throw new TypeError('canonical JSON invalid Unicode');
        }
      }
      return JSON.stringify(value);
    case 'object':
      if (Array.isArray(value)) return `[${value.map((item) => canonicalJSON(item, depth + 1)).join(',')}]`;
      // Default sort compares UTF-16 code units. Write fields explicitly since
      // JSON.stringify(object) reorders numeric keys after insertion.
      return `{${Object.keys(value)
        .sort()
        .map(
          (key) => `${canonicalJSON(key, depth + 1)}:${canonicalJSON((value as Record<string, unknown>)[key], depth + 1)}`,
        )
        .join(',')}}`;
    default:
      throw new TypeError('canonical JSON unsupported value');
  }
}
