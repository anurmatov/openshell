// SPDX-License-Identifier: Apache-2.0

import { type Client, Code, createClient, type Transport } from '@connectrpc/connect';
import type { CreateOwnershipKey } from './create-fingerprint.js';
import { fromConnect, SdkError } from './errors.js';
import { type GetSandboxCreateReceiptResponse, OpenShell } from './gen/openshell_pb.js';

export type CreateReceiptState = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
export type CreateEffectState = 1 | 2 | 3 | 4;
/** Exact timestamp, without losing nanoseconds or uint64 precision. */
export interface OwnershipTimestamp {
  readonly seconds: bigint;
  readonly nanos: number;
}
export interface CreateOwnershipBinding {
  readonly claimIncarnationID: string;
  readonly sandboxID: string;
  readonly initialResourceVersion: bigint;
  readonly currentResourceVersion?: bigint;
  readonly currentState: string;
  readonly effectState: CreateEffectState;
  readonly bindingRevision: bigint;
}
/** Complete describes the Create result, never runtime or broker absence. */
export interface CreateOwnershipReceipt {
  readonly state: CreateReceiptState;
  readonly requestID: string;
  readonly fingerprint: Uint8Array;
  readonly schemaDigest: string;
  readonly revision: bigint;
  readonly createdAt?: OwnershipTimestamp;
  readonly completedAt?: OwnershipTimestamp;
  readonly expiresAt?: OwnershipTimestamp;
  readonly coverageEpoch: string;
  readonly bindings: readonly CreateOwnershipBinding[];
  readonly complete: boolean;
  readonly fenceRevision: bigint;
  readonly admissionClosed: boolean;
  readonly reasonCode: string;
}
export interface CreateOwnershipCallOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}
const uuid = (value: string): boolean =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) &&
  value !== '00000000-0000-0000-0000-000000000000';

function freezeKey(workspace: string, key: CreateOwnershipKey, expected?: string): CreateOwnershipKey {
  if (
    !workspace ||
    workspace !== workspace.trim() ||
    workspace === '*' ||
    !uuid(key.requestID) ||
    key.fingerprint.length !== 32 ||
    !/^[0-9a-f]{64}$/.test(key.schemaDigest) ||
    (expected !== undefined && !uuid(expected))
  ) {
    throw new SdkError('invalid_config', 'named workspace and canonical original Create key required');
  }
  return { requestID: key.requestID, schemaDigest: key.schemaDigest, fingerprint: new Uint8Array(key.fingerprint) };
}

function decode(
  r: GetSandboxCreateReceiptResponse | undefined,
  key: CreateOwnershipKey,
  expected?: string,
): CreateOwnershipReceipt {
  const invalid = (): never => {
    throw new SdkError('rpc', 'invalid Create ownership receipt');
  };
  if (
    !r ||
    r.requestId !== key.requestID ||
    r.fingerprintSchemaDigest !== key.schemaDigest ||
    r.fingerprint.length !== 32 ||
    !r.fingerprint.every((v, i) => v === key.fingerprint[i]) ||
    r.receiptState < 1 ||
    r.receiptState > 9 ||
    r.bindings.length > 16 ||
    !r.coverageEpoch
  )
    return invalid();
  const state = r.receiptState;
  if (
    (r.complete && ![2, 4, 8].includes(state)) ||
    (state === 8 && (!r.admissionClosed || r.fenceRevision === 0n || r.bindings.length !== 0)) ||
    (state === 9 && (!r.admissionClosed || r.fenceRevision === 0n)) ||
    (state === 4 && (!r.admissionClosed || !r.completedAt || r.bindings.length !== 0)) ||
    ([2, 5].includes(state) && (!r.completedAt || r.bindings.length !== 1)) ||
    (![6, 7].includes(state) && (r.receiptRevision === 0n || !r.createdAt))
  )
    return invalid();
  const timestamp = (value?: OwnershipTimestamp): OwnershipTimestamp | undefined => {
    if (!value) return undefined;
    if (
      value.seconds < -62135596800n ||
      value.seconds > 253402300799n ||
      !Number.isInteger(value.nanos) ||
      value.nanos < 0 ||
      value.nanos >= 1e9
    )
      return invalid();
    return { seconds: value.seconds, nanos: value.nanos };
  };
  let matched = expected === undefined || [6, 7].includes(state);
  const seen = new Set<string>();
  const bindings = r.bindings.map((b): CreateOwnershipBinding => {
    if (
      !uuid(b.sandboxId) ||
      !uuid(b.claimIncarnationId) ||
      b.initialResourceVersion === 0n ||
      b.bindingRevision === 0n ||
      b.currentResourceVersion === 0n ||
      b.effectState < 1 ||
      b.effectState > 4 ||
      seen.has(b.sandboxId) ||
      (b.effectState === 4) !== (r.completedAt !== undefined)
    )
      return invalid();
    seen.add(b.sandboxId);
    matched ||= b.sandboxId === expected;
    return {
      claimIncarnationID: b.claimIncarnationId,
      sandboxID: b.sandboxId,
      initialResourceVersion: b.initialResourceVersion,
      currentResourceVersion: b.currentResourceVersion,
      currentState: b.currentState,
      effectState: b.effectState as CreateEffectState,
      bindingRevision: b.bindingRevision,
    };
  });
  if (!matched) return invalid();
  return {
    state: state as CreateReceiptState,
    requestID: r.requestId,
    fingerprint: new Uint8Array(r.fingerprint),
    schemaDigest: r.fingerprintSchemaDigest,
    revision: r.receiptRevision,
    createdAt: timestamp(r.createdAt),
    completedAt: timestamp(r.completedAt),
    expiresAt: timestamp(r.expiresAt),
    coverageEpoch: r.coverageEpoch,
    bindings,
    complete: r.complete,
    fenceRevision: r.fenceRevision,
    admissionClosed: r.admissionClosed,
    reasonCode: r.reasonCode,
  };
}

/**
 * Additive receipt/fence client over an existing authenticated transport.
 * It never sends Create or selects a replacement. Supply a transport without
 * mutation-retry interceptors. Health is fresh per call but cannot prevent a
 * downgrade between discovery and the RPC; the server must enforce the contract.
 */
export class CreateOwnershipClient {
  private readonly grpc: Client<typeof OpenShell>;
  constructor(transport: Transport) {
    this.grpc = createClient(OpenShell, transport);
  }
  private async requireCapability(options?: CreateOwnershipCallOptions): Promise<void> {
    if (options?.timeoutMs !== undefined && (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0)) {
      throw new SdkError('invalid_config', 'timeoutMs must be finite and positive');
    }
    const health = await this.grpc.health({}, options);
    if (!health.capabilities.includes('sandbox-create-ownership-v1')) {
      throw new SdkError('rpc', 'gateway capability sandbox-create-ownership-v1 required', {
        connectCode: Code.Unimplemented,
      });
    }
  }
  /** One SELECT-only RPC; missing/expired evidence never triggers a fence. */
  async get(
    workspace: string,
    key: CreateOwnershipKey,
    expectedSandboxID?: string,
    options?: CreateOwnershipCallOptions,
  ): Promise<CreateOwnershipReceipt> {
    const original = freezeKey(workspace, key, expectedSandboxID);
    try {
      await this.requireCapability(options);
      const response = await this.grpc.getSandboxCreateReceipt(
        {
          workspaceScope: { selection: { case: 'workspace', value: workspace } },
          requestId: original.requestID,
          payloadFingerprint: original.fingerprint,
          fingerprintSchemaDigest: original.schemaDigest,
          expectedSandboxId: expectedSandboxID,
        },
        options,
      );
      return decode(response, original, expectedSandboxID);
    } catch (error) {
      throw fromConnect(error);
    }
  }
  /**
   * Explicit metadata fence, not cancellation or absence proof.
   * A lost reply is an error, never permission to resend; use get for readback.
   */
  async fence(
    workspace: string,
    key: CreateOwnershipKey,
    options?: CreateOwnershipCallOptions,
  ): Promise<CreateOwnershipReceipt> {
    const original = freezeKey(workspace, key);
    try {
      await this.requireCapability(options);
      const response = await this.grpc.fenceSandboxCreate(
        {
          workspaceScope: { selection: { case: 'workspace', value: workspace } },
          requestId: original.requestID,
          payloadFingerprint: original.fingerprint,
          fingerprintSchemaDigest: original.schemaDigest,
        },
        options,
      );
      const result = decode(response.receipt, original);
      if (!result.admissionClosed || result.fenceRevision === 0n)
        throw new SdkError('rpc', 'Create fence was not confirmed closed');
      return result;
    } catch (error) {
      throw fromConnect(error);
    }
  }
}
