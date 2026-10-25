// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCreateOwnershipReceiptDeepCopiesWireFields(t *testing.T) {
	request := "11111111-1111-4111-8111-111111111111"
	sandbox := "22222222-2222-4222-8222-222222222222"
	claim := "33333333-3333-4333-8333-333333333333"
	key := types.CreateOwnershipKey{RequestID: request, Fingerprint: make([]byte, 32), SchemaDigest: strings.Repeat("a", 64)}
	current := uint64(4)
	wire := &pb.GetSandboxCreateReceiptResponse{RequestId: request, Fingerprint: make([]byte, 32), FingerprintSchemaDigest: key.SchemaDigest,
		CoverageEpoch: claim, ReceiptState: pb.CreateReceiptState_CREATE_RECEIPT_STATE_SUCCEEDED, ReceiptRevision: 1, CreatedAt: timestamppb.New(time.Unix(100, 0)),
		CompletedAt: timestamppb.New(time.Unix(101, 0)), Complete: true, Bindings: []*pb.CreateOwnershipBinding{{ClaimIncarnationId: claim, SandboxId: sandbox,
			InitialResourceVersion: 1, CurrentResourceVersion: &current, BindingRevision: 1, EffectState: pb.CreateEffectState_CREATE_EFFECT_STATE_OWNER_TERMINAL}}}
	copied, err := CreateOwnershipReceiptFromProto(wire, key, sandbox)
	require.NoError(t, err)
	wire.Fingerprint[0] = 9
	*wire.Bindings[0].CurrentResourceVersion = 9
	wire.CreatedAt.Seconds = 999
	require.Equal(t, byte(0), copied.Fingerprint[0])
	require.Equal(t, uint64(4), *copied.Bindings[0].CurrentResourceVersion)
	require.Equal(t, int64(100), copied.CreatedAt.Unix())
}

func TestCreateOwnershipReceiptRejectsNonterminalEffectsForTerminalReceipts(t *testing.T) {
	key := types.CreateOwnershipKey{RequestID: "11111111-1111-4111-8111-111111111111", Fingerprint: make([]byte, 32), SchemaDigest: strings.Repeat("a", 64)}
	for _, state := range []pb.CreateReceiptState{pb.CreateReceiptState_CREATE_RECEIPT_STATE_SUCCEEDED, pb.CreateReceiptState_CREATE_RECEIPT_STATE_EXPIRED} {
		for _, effect := range []pb.CreateEffectState{pb.CreateEffectState_CREATE_EFFECT_STATE_NOT_STARTED, pb.CreateEffectState_CREATE_EFFECT_STATE_RESOURCE_COMMITTED, pb.CreateEffectState_CREATE_EFFECT_STATE_DRIVER_STARTED, pb.CreateEffectState_CREATE_EFFECT_STATE_OWNER_TERMINAL} {
			t.Run(state.String()+"/"+effect.String(), func(t *testing.T) {
				wire := &pb.GetSandboxCreateReceiptResponse{RequestId: key.RequestID, Fingerprint: key.Fingerprint, FingerprintSchemaDigest: key.SchemaDigest,
					CoverageEpoch: "33333333-3333-4333-8333-333333333333", ReceiptState: state, ReceiptRevision: 1, CreatedAt: timestamppb.New(time.Unix(100, 0)),
					CompletedAt: timestamppb.New(time.Unix(101, 0)), Complete: state == pb.CreateReceiptState_CREATE_RECEIPT_STATE_SUCCEEDED,
					Bindings: []*pb.CreateOwnershipBinding{{ClaimIncarnationId: "33333333-3333-4333-8333-333333333333", SandboxId: "22222222-2222-4222-8222-222222222222",
						InitialResourceVersion: 1, BindingRevision: 1, EffectState: effect}}}
				got, err := CreateOwnershipReceiptFromProto(wire, key, "")
				if effect == pb.CreateEffectState_CREATE_EFFECT_STATE_OWNER_TERMINAL {
					require.NoError(t, err)
					require.Equal(t, wire.Complete, got.Complete)
				} else {
					require.Error(t, err)
					require.Nil(t, got)
				}
			})
		}
	}
}
