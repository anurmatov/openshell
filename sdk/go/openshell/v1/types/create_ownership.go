// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// CreateOwnershipKey identifies an original Create, never a name-based replacement.
// Fingerprint is the approved canonical original request projection, not a hash
// of the generated protobuf bytes. SchemaDigest identifies that projection.
type CreateOwnershipKey struct {
	RequestID    string
	Fingerprint  []byte
	SchemaDigest string
}

// CreateReceiptState describes ownership only, never runtime or broker readiness.
type CreateReceiptState int32

const (
	CreateReceiptUnspecified CreateReceiptState = iota
	CreateReceiptPending
	CreateReceiptSucceeded
	CreateReceiptAmbiguous
	CreateReceiptNoResource
	CreateReceiptExpired
	CreateReceiptNotFoundAsOfRead
	CreateReceiptUnsupportedCoverage
	CreateReceiptAbandoned
	CreateReceiptFencedPending
)

// CreateEffectState describes a recorded effect boundary, not current liveness.
type CreateEffectState int32

const (
	CreateEffectUnspecified CreateEffectState = iota
	CreateEffectNotStarted
	CreateEffectResourceCommitted
	CreateEffectDriverStarted
	CreateEffectOwnerTerminal
)

// CreateOwnershipBinding is immutable original ownership. CurrentState is diagnostic.
type CreateOwnershipBinding struct {
	ClaimIncarnationID     string
	SandboxID              string
	InitialResourceVersion uint64
	CurrentResourceVersion *uint64
	CurrentState           string
	EffectState            CreateEffectState
	BindingRevision        uint64
}

// CreateOwnershipReceipt retains incomplete/expired/unsupported evidence as-is.
// Complete refers to the recorded Create result, not absence of any runtime,
// process, socket, poller or broker consumer. Reads never fence or replay Create.
type CreateOwnershipReceipt struct {
	State           CreateReceiptState
	RequestID       string
	Fingerprint     []byte
	Revision        uint64
	CreatedAt       *time.Time
	CompletedAt     *time.Time
	ExpiresAt       *time.Time
	CoverageEpoch   string
	Bindings        []CreateOwnershipBinding
	Complete        bool
	SchemaDigest    string
	FenceRevision   uint64
	AdmissionClosed bool
	ReasonCode      string
}
