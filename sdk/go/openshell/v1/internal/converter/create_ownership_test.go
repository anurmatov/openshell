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
