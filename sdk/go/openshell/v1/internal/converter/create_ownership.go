// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"bytes"
	"errors"
	"regexp"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ownershipIdentity = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validOwnershipIdentity(id string) bool {
	return ownershipIdentity.MatchString(id) && id != "00000000-0000-0000-0000-000000000000"
}

// CreateOwnershipReceiptFromProto validates original-key linkage and deep-copies
// every mutable field. Unknown/contradictory evidence is an error, never absence.
func CreateOwnershipReceiptFromProto(r *pb.GetSandboxCreateReceiptResponse, key types.CreateOwnershipKey, expected string) (*types.CreateOwnershipReceipt, error) {
	invalid := errors.New("ownership receipt violates identity, shape or terminal invariants")
	if r == nil || r.RequestId != key.RequestID || !bytes.Equal(r.Fingerprint, key.Fingerprint) || r.FingerprintSchemaDigest != key.SchemaDigest ||
		r.ReceiptState < 1 || r.ReceiptState > 9 || len(r.Bindings) > 16 || r.CoverageEpoch == "" {
		return nil, invalid
	}
	state := types.CreateReceiptState(r.ReceiptState)
	if r.Complete && state != types.CreateReceiptSucceeded && state != types.CreateReceiptNoResource && state != types.CreateReceiptAbandoned {
		return nil, invalid
	}
	if state == types.CreateReceiptAbandoned && (!r.AdmissionClosed || r.FenceRevision == 0 || len(r.Bindings) != 0) {
		return nil, invalid
	}
	if state == types.CreateReceiptFencedPending && (!r.AdmissionClosed || r.FenceRevision == 0) {
		return nil, invalid
	}
	if state == types.CreateReceiptNoResource && (!r.AdmissionClosed || r.CompletedAt == nil || len(r.Bindings) != 0) {
		return nil, invalid
	}
	if state == types.CreateReceiptSucceeded && (r.CompletedAt == nil || len(r.Bindings) != 1) {
		return nil, invalid
	}
	if state != types.CreateReceiptNotFoundAsOfRead && state != types.CreateReceiptUnsupportedCoverage && (r.ReceiptRevision == 0 || r.CreatedAt == nil) {
		return nil, invalid
	}
	result := &types.CreateOwnershipReceipt{State: state, RequestID: r.RequestId, Fingerprint: append([]byte(nil), r.Fingerprint...), Revision: r.ReceiptRevision,
		CoverageEpoch: r.CoverageEpoch, Complete: r.Complete, SchemaDigest: r.FingerprintSchemaDigest, FenceRevision: r.FenceRevision,
		AdmissionClosed: r.AdmissionClosed, ReasonCode: r.ReasonCode}
	for _, field := range []struct {
		wire *timestamppb.Timestamp
		out  **time.Time
	}{{r.CreatedAt, &result.CreatedAt}, {r.CompletedAt, &result.CompletedAt}, {r.ExpiresAt, &result.ExpiresAt}} {
		if field.wire != nil {
			if field.wire.CheckValid() != nil {
				return nil, invalid
			}
			value := field.wire.AsTime()
			*field.out = &value
		}
	}
	// A qualified missing-key read still says nothing about the expected ID.
	// Preserve its incomplete state rather than turn it into absence or a target.
	matched := expected == "" || state == types.CreateReceiptNotFoundAsOfRead || state == types.CreateReceiptUnsupportedCoverage
	seen := make(map[string]bool)
	for _, binding := range r.Bindings {
		if binding == nil || !validOwnershipIdentity(binding.SandboxId) || !validOwnershipIdentity(binding.ClaimIncarnationId) || binding.InitialResourceVersion == 0 || binding.BindingRevision == 0 ||
			binding.EffectState < 1 || binding.EffectState > 4 || seen[binding.SandboxId] || binding.CurrentResourceVersion != nil && *binding.CurrentResourceVersion == 0 {
			return nil, invalid
		}
		seen[binding.SandboxId] = true
		matched = matched || binding.SandboxId == expected
		copied := types.CreateOwnershipBinding{ClaimIncarnationID: binding.ClaimIncarnationId, SandboxID: binding.SandboxId,
			InitialResourceVersion: binding.InitialResourceVersion, CurrentState: binding.CurrentState, EffectState: types.CreateEffectState(binding.EffectState), BindingRevision: binding.BindingRevision}
		if binding.CurrentResourceVersion != nil {
			v := *binding.CurrentResourceVersion
			copied.CurrentResourceVersion = &v
		}
		result.Bindings = append(result.Bindings, copied)
	}
	if !matched {
		return nil, invalid
	}
	return result, nil
}
