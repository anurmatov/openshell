// SPDX-License-Identifier: Apache-2.0
import { createRouterTransport, type ServiceImpl } from '@connectrpc/connect';
import { describe, expect, it } from 'vitest';
import { CreateOwnershipClient } from './create-ownership.js';
import { OpenShell } from './gen/openshell_pb.js';

const id = '11111111-1111-4111-8111-111111111111';
const sandbox = '22222222-2222-4222-8222-222222222222';
const claim = '33333333-3333-4333-8333-333333333333';
const key = () => ({ requestID: id, fingerprint: new Uint8Array(32).fill(7), schemaDigest: 'a'.repeat(64) });
function receipt() {
  return {
    requestId: id,
    fingerprint: key().fingerprint,
    fingerprintSchemaDigest: key().schemaDigest,
    receiptState: 2,
    receiptRevision: 1n,
    coverageEpoch: 'epoch-a',
    createdAt: { seconds: 1n, nanos: 0 },
    completedAt: { seconds: 2n, nanos: 0 },
    complete: true,
    admissionClosed: false,
    fenceRevision: 0n,
    bindings: [
      {
        claimIncarnationId: claim,
        sandboxId: sandbox,
        initialResourceVersion: 1n,
        currentResourceVersion: 2n,
        currentState: 'READY',
        effectState: 4,
        bindingRevision: 1n,
      },
    ],
  };
}
function client(impl: Partial<ServiceImpl<typeof OpenShell>>) {
  return new CreateOwnershipClient(createRouterTransport((router) => router.service(OpenShell, impl)));
}
describe('Create ownership curated transport', () => {
  it('reads one original key through the generated transport without lifecycle calls', async () => {
    let reads = 0;
    let health = 0;
    let mutations = 0;
    const api = client({
      health: () => {
        health++;
        return { capabilities: ['sandbox-create-ownership-v1'] };
      },
      getSandboxCreateReceipt: (req) => {
        reads++;
        expect(req.workspaceScope?.selection).toEqual({ case: 'workspace', value: 'workspace-a' });
        expect(req.requestId).toBe(id);
        expect(req.expectedSandboxId).toBe(sandbox);
        return receipt();
      },
      createSandbox: () => {
        mutations++;
        throw Error('must not run');
      },
      fenceSandboxCreate: () => {
        mutations++;
        throw Error('must not run');
      },
    });
    const result = await api.get('workspace-a', key(), sandbox);
    expect(result.state).toBe(2);
    expect(result.bindings[0]?.sandboxID).toBe(sandbox);
    expect({ reads, health, mutations }).toEqual({ reads: 1, health: 1, mutations: 0 });
  });
  it('refuses a capability downgrade on each operation with zero ownership calls', async () => {
    let capable = true;
    let reads = 0;
    let fences = 0;
    let health = 0;
    const api = client({
      health: () => {
        health++;
        return { capabilities: capable ? ['sandbox-create-ownership-v1'] : [] };
      },
      getSandboxCreateReceipt: () => {
        reads++;
        return receipt();
      },
      fenceSandboxCreate: () => {
        fences++;
        return { receipt: receipt() };
      },
    });
    await api.get('workspace-a', key());
    capable = false;
    await expect(api.get('workspace-a', key())).rejects.toThrow('capability');
    await expect(api.fence('workspace-a', key())).rejects.toThrow('capability');
    expect({ reads, fences, health }).toEqual({ reads: 1, fences: 0, health: 3 });
  });
  it.each([
    [
      'unknown',
      (r: ReturnType<typeof receipt>) => {
        r.receiptState = 99;
      },
    ],
    [
      'wrong UUID',
      (r: ReturnType<typeof receipt>) => {
        r.requestId = sandbox;
      },
    ],
    [
      'wrong fingerprint',
      (r: ReturnType<typeof receipt>) => {
        r.fingerprint.fill(0);
      },
    ],
    [
      'wrong schema',
      (r: ReturnType<typeof receipt>) => {
        r.fingerprintSchemaDigest = 'b'.repeat(64);
      },
    ],
    [
      'missing epoch',
      (r: ReturnType<typeof receipt>) => {
        r.coverageEpoch = '';
      },
    ],
    [
      'zero revision',
      (r: ReturnType<typeof receipt>) => {
        r.receiptRevision = 0n;
      },
    ],
    [
      'bad timestamp',
      (r: ReturnType<typeof receipt>) => {
        r.createdAt.nanos = 1e9;
      },
    ],
    [
      'nonterminal success',
      (r: ReturnType<typeof receipt>) => {
        r.bindings[0].effectState = 1;
      },
    ],
    [
      'false not bypass',
      (r: ReturnType<typeof receipt>) => {
        r.complete = false;
        r.bindings[0].effectState = 1;
      },
    ],
    [
      'duplicate binding',
      (r: ReturnType<typeof receipt>) => {
        r.bindings.push({ ...r.bindings[0] });
      },
    ],
    [
      'zero initial version',
      (r: ReturnType<typeof receipt>) => {
        r.bindings[0].initialResourceVersion = 0n;
      },
    ],
    [
      'zero current version',
      (r: ReturnType<typeof receipt>) => {
        r.bindings[0].currentResourceVersion = 0n;
      },
    ],
    [
      'foreign sandbox',
      (r: ReturnType<typeof receipt>) => {
        r.bindings[0].sandboxId = claim;
      },
    ],
    [
      'unclosed abandoned',
      (r: ReturnType<typeof receipt>) => {
        r.receiptState = 8;
        r.bindings = [];
      },
    ],
    [
      'unclosed fenced',
      (r: ReturnType<typeof receipt>) => {
        r.receiptState = 9;
        r.complete = false;
      },
    ],
    [
      'complete pending',
      (r: ReturnType<typeof receipt>) => {
        r.receiptState = 1;
      },
    ],
  ])('rejects contradictory %s through public Get', async (_, alter) => {
    const r = receipt();
    alter(r);
    const api = client({
      health: () => ({ capabilities: ['sandbox-create-ownership-v1'] }),
      getSandboxCreateReceipt: () => r,
    });
    await expect(api.get('workspace-a', key(), sandbox)).rejects.toThrow('invalid Create ownership receipt');
  });
  it('freezes input before Health and copies output bytes', async () => {
    const k = key();
    const r = receipt();
    const api = client({
      health: () => {
        k.fingerprint.fill(0);
        return { capabilities: ['sandbox-create-ownership-v1'] };
      },
      getSandboxCreateReceipt: (req) => {
        expect(req.payloadFingerprint[0]).toBe(7);
        return r;
      },
    });
    const result = await api.get('workspace-a', k);
    r.fingerprint.fill(0);
    expect(result.fingerprint[0]).toBe(7);
  });
  it('retains an incomplete missing key without selecting the expected target', async () => {
    const api = client({
      health: () => ({ capabilities: ['sandbox-create-ownership-v1'] }),
      getSandboxCreateReceipt: () => ({
        ...receipt(),
        receiptState: 6,
        complete: false,
        bindings: [],
        receiptRevision: 0n,
      }),
    });
    const result = await api.get('workspace-a', key(), sandbox);
    expect(result.complete).toBe(false);
    expect(result.bindings).toEqual([]);
  });
  it('sends explicit fence once and requires confirmed closure', async () => {
    let fences = 0;
    const api = client({
      health: () => ({ capabilities: ['sandbox-create-ownership-v1'] }),
      fenceSandboxCreate: () => {
        fences++;
        return { receipt: { ...receipt(), receiptState: 8, bindings: [], admissionClosed: true, fenceRevision: 1n } };
      },
    });
    expect((await api.fence('workspace-a', key())).state).toBe(8);
    expect(fences).toBe(1);
  });
  it('does not resend an ambiguous fence', async () => {
    let fences = 0;
    const api = client({
      health: () => ({ capabilities: ['sandbox-create-ownership-v1'] }),
      fenceSandboxCreate: () => {
        fences++;
        throw Error('lost reply');
      },
    });
    await expect(api.fence('workspace-a', key())).rejects.toThrow();
    expect(fences).toBe(1);
  });
  it.each(['', '*', ' workspace-a'])('rejects invalid workspace %s before Health', async (workspace) => {
    let calls = 0;
    const api = client({
      health: () => {
        calls++;
        return {};
      },
    });
    await expect(api.get(workspace, key())).rejects.toThrow();
    expect(calls).toBe(0);
  });
});
describe('Create receipt preservation and refusal', () => {
  it.each([1, 3, 5, 6, 7, 9])('preserves incomplete state %s without another RPC', async (state) => {
    let reads = 0;
    const r = {
      ...receipt(),
      receiptState: state,
      complete: false,
      admissionClosed: state === 9,
      fenceRevision: state === 9 ? 1n : 0n,
    };
    if (![5].includes(state)) {
      r.bindings = [];
    }
    const api = client({
      health: () => ({ capabilities: ['sandbox-create-ownership-v1'] }),
      getSandboxCreateReceipt: () => {
        reads++;
        return r;
      },
    });
    const result = await api.get('workspace-a', key());
    expect(result.state).toBe(state);
    expect(result.complete).toBe(false);
    expect(reads).toBe(1);
  });
  it('retains exact timestamps and uint64 values without float conversion', async () => {
    const r = receipt();
    r.receiptRevision = 18446744073709551615n;
    r.createdAt = { seconds: -62135596800n, nanos: 999999999 };
    r.bindings[0].initialResourceVersion = 18446744073709551615n;
    const api = client({
      health: () => ({ capabilities: ['sandbox-create-ownership-v1'] }),
      getSandboxCreateReceipt: () => r,
    });
    const result = await api.get('workspace-a', key());
    expect(result.revision).toBe(18446744073709551615n);
    expect(result.createdAt).toEqual(r.createdAt);
    expect(result.bindings[0]?.initialResourceVersion).toBe(18446744073709551615n);
  });
  it('requires positive closure for Fence even on a valid successful receipt', async () => {
    let fences = 0;
    const api = client({
      health: () => ({ capabilities: ['sandbox-create-ownership-v1'] }),
      fenceSandboxCreate: () => {
        fences++;
        return { receipt: receipt() };
      },
    });
    await expect(api.fence('workspace-a', key())).rejects.toThrow('not confirmed closed');
    expect(fences).toBe(1);
  });
  it('refuses invalid keys and timeout before any ownership mutation', async () => {
    let calls = 0;
    const api = client({
      health: () => {
        calls++;
        return {};
      },
    });
    await expect(api.get('workspace-a', { ...key(), requestID: 'not-a-uuid' })).rejects.toThrow();
    await expect(api.get('workspace-a', { ...key(), fingerprint: new Uint8Array(31) })).rejects.toThrow();
    await expect(api.get('workspace-a', { ...key(), schemaDigest: 'A'.repeat(64) })).rejects.toThrow();
    await expect(api.get('workspace-a', key(), 'same-name')).rejects.toThrow();
    await expect(api.fence('workspace-a', key(), { timeoutMs: 0 })).rejects.toThrow();
    expect(calls).toBe(0);
  });
  it('exports the actual curated client from the package root', async () => {
    const root = await import('./index.js');
    expect(root.CreateOwnershipClient).toBe(CreateOwnershipClient);
  });
});
