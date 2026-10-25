// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ownerRequest = "11111111-1111-4111-8111-111111111111"
const ownerSandbox = "22222222-2222-4222-8222-222222222222"
const ownerClaim = "33333333-3333-4333-8333-333333333333"

func ownerKey() CreateOwnershipKey {
	return CreateOwnershipKey{RequestID: ownerRequest, Fingerprint: make([]byte, 32), SchemaDigest: string(makeHex('a', 64))}
}
func makeHex(value byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = value
	}
	return out
}
func ownerReceipt() *pb.GetSandboxCreateReceiptResponse {
	return &pb.GetSandboxCreateReceiptResponse{RequestId: ownerRequest, Fingerprint: make([]byte, 32),
		FingerprintSchemaDigest: string(makeHex('a', 64)), CoverageEpoch: ownerClaim,
		ReceiptRevision: 1, CreatedAt: timestamppb.New(time.Unix(100, 0)),
		ReceiptState: pb.CreateReceiptState_CREATE_RECEIPT_STATE_PENDING}
}

type ownershipServer struct {
	pb.UnimplementedOpenShellServer
	mu                   sync.Mutex
	health, gets, fences int
	creates              int
	capabilities         []string
	err, healthErr       error
	fenceNotClosed       bool
	receipt              *pb.GetSandboxCreateReceiptResponse
	get                  *pb.GetSandboxCreateReceiptRequest
	fence                *pb.FenceSandboxCreateRequest
}

func (s *ownershipServer) CreateSandbox(context.Context, *pb.CreateSandboxRequest) (*pb.SandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates++
	return nil, status.Error(codes.FailedPrecondition, "synthetic Create must never be called")
}

func (s *ownershipServer) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health++
	return &pb.HealthResponse{Capabilities: append([]string(nil), s.capabilities...)}, s.healthErr
}
func (s *ownershipServer) GetSandboxCreateReceipt(_ context.Context, r *pb.GetSandboxCreateReceiptRequest) (*pb.GetSandboxCreateReceiptResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	s.get = proto.Clone(r).(*pb.GetSandboxCreateReceiptRequest)
	return s.receipt, s.err
}
func (s *ownershipServer) FenceSandboxCreate(_ context.Context, r *pb.FenceSandboxCreateRequest) (*pb.FenceSandboxCreateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fences++
	s.fence = proto.Clone(r).(*pb.FenceSandboxCreateRequest)
	var receipt *pb.GetSandboxCreateReceiptResponse
	if s.receipt != nil {
		receipt = proto.Clone(s.receipt).(*pb.GetSandboxCreateReceiptResponse)
		if !s.fenceNotClosed && receipt.ReceiptState == pb.CreateReceiptState_CREATE_RECEIPT_STATE_PENDING && !receipt.Complete {
			receipt.ReceiptState = pb.CreateReceiptState_CREATE_RECEIPT_STATE_FENCED_PENDING
			receipt.AdmissionClosed = true
			receipt.FenceRevision = 1
		}
	}
	return &pb.FenceSandboxCreateResponse{Receipt: receipt}, s.err
}
func ownershipFixture(t *testing.T) (*Client, *ownershipServer) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	s := &ownershipServer{capabilities: []string{"sandbox-create-ownership-v1"}, receipt: ownerReceipt()}
	pb.RegisterOpenShellServer(server, s)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///owned-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithDefaultServiceConfig(`{"methodConfig":[{"name":[{"service":"openshell.v1.OpenShell"}],"retryPolicy":{"maxAttempts":3,"initialBackoff":"0.001s","maxBackoff":"0.001s","backoffMultiplier":1,"retryableStatusCodes":["UNAVAILABLE"]}}]}`))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(); server.Stop(); _ = listener.Close() })
	return &Client{conn: conn}, s
}
func TestCreateOwnershipFreshHealthAndExactNamedWorkspace(t *testing.T) {
	c, s := ownershipFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	receipt, err := c.CreateOwnership().Get(ctx, "workspace-a", ownerKey(), "")
	require.NoError(t, err)
	require.False(t, receipt.Complete)
	require.Equal(t, CreateReceiptPending, receipt.State)
	_, err = c.CreateOwnership().Fence(ctx, "workspace-a", ownerKey())
	require.NoError(t, err)
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Equal(t, 2, s.health)
	require.Equal(t, 1, s.gets)
	require.Equal(t, 1, s.fences)
	require.Equal(t, "workspace-a", s.get.WorkspaceScope.GetWorkspace())
	require.Equal(t, "workspace-a", s.fence.WorkspaceScope.GetWorkspace())
	require.Equal(t, ownerRequest, s.get.RequestId)
	require.Equal(t, ownerKey().Fingerprint, s.get.PayloadFingerprint)
}
func TestCreateOwnershipDowngradeAndHealthFailureSendZero(t *testing.T) {
	for _, failure := range []string{"missing", "health-error"} {
		t.Run(failure, func(t *testing.T) {
			c, s := ownershipFixture(t)
			s.capabilities = nil
			if failure == "health-error" {
				s.healthErr = status.Error(codes.Unauthenticated, "synthetic")
			}
			_, err := c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), "")
			require.Error(t, err)
			_, err = c.CreateOwnership().Fence(context.Background(), "workspace-a", ownerKey())
			require.Error(t, err)
			require.Equal(t, 2, s.health)
			require.Zero(t, s.gets)
			require.Zero(t, s.fences)
		})
	}
}
func TestCreateOwnershipCapabilityIsNotCached(t *testing.T) {
	c, s := ownershipFixture(t)
	_, err := c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), "")
	require.NoError(t, err)
	s.mu.Lock()
	s.capabilities = nil
	s.mu.Unlock()
	_, err = c.CreateOwnership().Fence(context.Background(), "workspace-a", ownerKey())
	require.Error(t, err)
	require.Equal(t, 2, s.health)
	require.Equal(t, 1, s.gets)
	require.Zero(t, s.fences)
}

func TestCreateOwnershipRemoteDenialsNeverFallbackOrRetry(t *testing.T) {
	for _, code := range []codes.Code{codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition, codes.Aborted, codes.Unimplemented} {
		t.Run(code.String(), func(t *testing.T) {
			c, s := ownershipFixture(t)
			s.err = status.Error(code, "synthetic refusal")
			_, err := c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), "")
			require.Error(t, err)
			_, err = c.CreateOwnership().Fence(context.Background(), "workspace-a", ownerKey())
			require.Error(t, err)
			require.Equal(t, 1, s.gets)
			require.Equal(t, 1, s.fences)
			require.Zero(t, s.creates)
		})
	}
}

func TestCreateOwnershipAbandonedIsOnlyCreationEvidence(t *testing.T) {
	c, s := ownershipFixture(t)
	s.receipt.ReceiptState = pb.CreateReceiptState_CREATE_RECEIPT_STATE_ABANDONED
	s.receipt.Complete = true
	s.receipt.AdmissionClosed = true
	s.receipt.FenceRevision = 2
	r, err := c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), "")
	require.NoError(t, err)
	require.Equal(t, CreateReceiptAbandoned, r.State)
	require.True(t, r.Complete)
	require.Empty(t, r.Bindings)
	require.Equal(t, uint64(2), r.FenceRevision)
	require.Zero(t, s.fences)
	require.Zero(t, s.creates)
}
func TestCreateOwnershipNeverRetriesUncertainReceiptOrFence(t *testing.T) {
	c, s := ownershipFixture(t)
	s.err = status.Error(codes.Unavailable, "synthetic lost reply")
	_, err := c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), "")
	require.True(t, IsUnavailable(err))
	_, err = c.CreateOwnership().Fence(context.Background(), "workspace-a", ownerKey())
	require.True(t, IsUnavailable(err))
	require.Equal(t, 1, s.gets)
	require.Equal(t, 1, s.fences)
}
func TestCreateOwnershipRejectsMalformedKeysBeforeRPC(t *testing.T) {
	for _, test := range []struct {
		name, workspace, expected string
		key                       CreateOwnershipKey
	}{
		{"workspace-empty", "", "", ownerKey()}, {"workspace-all", "*", "", ownerKey()},
		{"uuid-uppercase", "workspace-a", "", CreateOwnershipKey{RequestID: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", Fingerprint: make([]byte, 32), SchemaDigest: string(makeHex('a', 64))}},
		{"uuid-nil", "workspace-a", "", CreateOwnershipKey{RequestID: "00000000-0000-0000-0000-000000000000", Fingerprint: make([]byte, 32), SchemaDigest: string(makeHex('a', 64))}},
		{"fingerprint", "workspace-a", "", CreateOwnershipKey{RequestID: ownerRequest, Fingerprint: make([]byte, 31), SchemaDigest: string(makeHex('a', 64))}},
		{"schema", "workspace-a", "", CreateOwnershipKey{RequestID: ownerRequest, Fingerprint: make([]byte, 32), SchemaDigest: "unknown"}},
		{"expected-id", "workspace-a", "same-name", ownerKey()},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, s := ownershipFixture(t)
			_, err := c.CreateOwnership().Get(context.Background(), test.workspace, test.key, test.expected)
			require.True(t, IsInvalidArgument(err))
			if test.expected == "" {
				_, err = c.CreateOwnership().Fence(context.Background(), test.workspace, test.key)
				require.True(t, IsInvalidArgument(err))
			}
			require.Zero(t, s.health)
			require.Zero(t, s.gets)
			require.Zero(t, s.fences)
		})
	}
}
func TestCreateOwnershipRejectsContradictoryAndForeignResponses(t *testing.T) {
	for _, fault := range []string{"foreign-uuid", "foreign-fingerprint", "foreign-schema", "unknown-state", "pending-complete", "abandoned-open", "binding-overflow", "nil-fence", "bad-time", "fence-not-closed"} {
		t.Run(fault, func(t *testing.T) {
			c, s := ownershipFixture(t)
			switch fault {
			case "foreign-uuid":
				s.receipt.RequestId = ownerSandbox
			case "foreign-fingerprint":
				s.receipt.Fingerprint[0] = 1
			case "foreign-schema":
				s.receipt.FingerprintSchemaDigest = string(makeHex('b', 64))
			case "unknown-state":
				s.receipt.ReceiptState = 999
			case "pending-complete":
				s.receipt.Complete = true
			case "abandoned-open":
				s.receipt.ReceiptState = pb.CreateReceiptState_CREATE_RECEIPT_STATE_ABANDONED
				s.receipt.Complete = true
			case "binding-overflow":
				s.receipt.Bindings = make([]*pb.CreateOwnershipBinding, 17)
			case "nil-fence":
				s.receipt = nil
			case "bad-time":
				s.receipt.CreatedAt = &timestamppb.Timestamp{Seconds: 1 << 62}
			case "fence-not-closed":
				s.fenceNotClosed = true
			}
			_, err := c.CreateOwnership().Fence(context.Background(), "workspace-a", ownerKey())
			require.Error(t, err)
			require.Equal(t, 1, s.fences)
		})
	}
}
func TestCreateOwnershipPreservesExpiredAndMissingWithoutAbsence(t *testing.T) {
	for _, state := range []pb.CreateReceiptState{pb.CreateReceiptState_CREATE_RECEIPT_STATE_EXPIRED, pb.CreateReceiptState_CREATE_RECEIPT_STATE_NOT_FOUND_AS_OF_READ, pb.CreateReceiptState_CREATE_RECEIPT_STATE_UNSUPPORTED_COVERAGE} {
		t.Run(state.String(), func(t *testing.T) {
			c, s := ownershipFixture(t)
			s.receipt.ReceiptState = state
			if state == pb.CreateReceiptState_CREATE_RECEIPT_STATE_EXPIRED {
				s.receipt.CompletedAt = timestamppb.New(time.Unix(101, 0))
				s.receipt.Bindings = []*pb.CreateOwnershipBinding{{ClaimIncarnationId: ownerClaim, SandboxId: ownerSandbox,
					InitialResourceVersion: 1, BindingRevision: 1, EffectState: pb.CreateEffectState_CREATE_EFFECT_STATE_OWNER_TERMINAL}}
			}
			expected := ""
			if state == pb.CreateReceiptState_CREATE_RECEIPT_STATE_NOT_FOUND_AS_OF_READ {
				expected = ownerSandbox
			}
			r, err := c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), expected)
			require.NoError(t, err)
			require.False(t, r.Complete)
			require.Equal(t, int32(state), int32(r.State))
			require.Zero(t, s.fences)
		})
	}
}
func TestCreateOwnershipExactBindingAndIndependentCopies(t *testing.T) {
	c, s := ownershipFixture(t)
	version := uint64(4)
	s.receipt.Bindings = []*pb.CreateOwnershipBinding{{ClaimIncarnationId: ownerClaim, SandboxId: ownerSandbox,
		InitialResourceVersion: 1, CurrentResourceVersion: &version, EffectState: pb.CreateEffectState_CREATE_EFFECT_STATE_OWNER_TERMINAL, BindingRevision: 1}}
	s.receipt.ReceiptState = pb.CreateReceiptState_CREATE_RECEIPT_STATE_SUCCEEDED
	s.receipt.CompletedAt = timestamppb.New(time.Unix(101, 0))
	s.receipt.Complete = true
	r, err := c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), ownerSandbox)
	require.NoError(t, err)
	require.Equal(t, ownerSandbox, *s.get.ExpectedSandboxId)
	require.Equal(t, uint64(4), *r.Bindings[0].CurrentResourceVersion)
	s.receipt.Fingerprint[0] = 9
	*s.receipt.Bindings[0].CurrentResourceVersion = 8
	require.Equal(t, byte(0), r.Fingerprint[0])
	require.Equal(t, uint64(4), *r.Bindings[0].CurrentResourceVersion)
	s.receipt.Fingerprint[0] = 0
	_, err = c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), ownerClaim)
	require.Error(t, err)
}

func TestCreateOwnershipGetRejectsContradictoryTerminalEffects(t *testing.T) {
	for _, state := range []pb.CreateReceiptState{pb.CreateReceiptState_CREATE_RECEIPT_STATE_SUCCEEDED, pb.CreateReceiptState_CREATE_RECEIPT_STATE_EXPIRED} {
		for _, effect := range []pb.CreateEffectState{pb.CreateEffectState_CREATE_EFFECT_STATE_NOT_STARTED, pb.CreateEffectState_CREATE_EFFECT_STATE_RESOURCE_COMMITTED, pb.CreateEffectState_CREATE_EFFECT_STATE_DRIVER_STARTED, pb.CreateEffectState_CREATE_EFFECT_STATE_OWNER_TERMINAL} {
			t.Run(state.String()+"/"+effect.String(), func(t *testing.T) {
				c, s := ownershipFixture(t)
				s.receipt.ReceiptState = state
				s.receipt.Complete = state == pb.CreateReceiptState_CREATE_RECEIPT_STATE_SUCCEEDED
				s.receipt.CompletedAt = timestamppb.New(time.Unix(101, 0))
				s.receipt.Bindings = []*pb.CreateOwnershipBinding{{ClaimIncarnationId: ownerClaim, SandboxId: ownerSandbox, InitialResourceVersion: 1, BindingRevision: 1, EffectState: effect}}
				got, err := c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), ownerSandbox)
				if effect == pb.CreateEffectState_CREATE_EFFECT_STATE_OWNER_TERMINAL {
					require.NoError(t, err)
					require.Equal(t, s.receipt.Complete, got.Complete)
				} else {
					require.Error(t, err)
					require.Nil(t, got)
					var statusError *StatusError
					require.ErrorAs(t, err, &statusError)
					require.Equal(t, ErrorUnavailable, statusError.Code)
				}
				require.Equal(t, 1, s.health)
				require.Equal(t, 1, s.gets)
				require.Zero(t, s.fences)
				require.Zero(t, s.creates)
			})
		}
	}
}

func TestCreateOwnershipGetRejectsTerminalMetadataContradictions(t *testing.T) {
	for _, name := range []string{"success-incomplete-not-started", "success-missing-completion", "expired-missing-completion", "expired-missing-binding", "pending-terminal-without-completion", "ambiguous-completed-driver-started"} {
		t.Run(name, func(t *testing.T) {
			c, s := ownershipFixture(t)
			s.receipt.ReceiptState = pb.CreateReceiptState_CREATE_RECEIPT_STATE_SUCCEEDED
			s.receipt.CompletedAt = timestamppb.New(time.Unix(101, 0))
			s.receipt.Bindings = []*pb.CreateOwnershipBinding{{ClaimIncarnationId: ownerClaim, SandboxId: ownerSandbox, InitialResourceVersion: 1, BindingRevision: 1,
				EffectState: pb.CreateEffectState_CREATE_EFFECT_STATE_OWNER_TERMINAL}}
			switch name {
			case "success-incomplete-not-started":
				s.receipt.Bindings[0].EffectState = pb.CreateEffectState_CREATE_EFFECT_STATE_NOT_STARTED
			case "success-missing-completion":
				s.receipt.CompletedAt = nil
			case "expired-missing-completion":
				s.receipt.ReceiptState = pb.CreateReceiptState_CREATE_RECEIPT_STATE_EXPIRED
				s.receipt.CompletedAt = nil
			case "expired-missing-binding":
				s.receipt.ReceiptState = pb.CreateReceiptState_CREATE_RECEIPT_STATE_EXPIRED
				s.receipt.Bindings = nil
			case "pending-terminal-without-completion":
				s.receipt.ReceiptState = pb.CreateReceiptState_CREATE_RECEIPT_STATE_PENDING
				s.receipt.CompletedAt = nil
			case "ambiguous-completed-driver-started":
				s.receipt.ReceiptState = pb.CreateReceiptState_CREATE_RECEIPT_STATE_AMBIGUOUS
				s.receipt.Bindings[0].EffectState = pb.CreateEffectState_CREATE_EFFECT_STATE_DRIVER_STARTED
			}
			got, err := c.CreateOwnership().Get(context.Background(), "workspace-a", ownerKey(), "")
			require.Error(t, err)
			require.Nil(t, got)
			require.Equal(t, 1, s.health)
			require.Equal(t, 1, s.gets)
			require.Zero(t, s.fences)
			require.Zero(t, s.creates)
		})
	}
}
