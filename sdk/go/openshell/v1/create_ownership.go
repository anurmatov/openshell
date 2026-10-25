// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type CreateOwnershipKey = types.CreateOwnershipKey
type CreateReceiptState = types.CreateReceiptState
type CreateEffectState = types.CreateEffectState
type CreateOwnershipBinding = types.CreateOwnershipBinding
type CreateOwnershipReceipt = types.CreateOwnershipReceipt

const (
	CreateReceiptUnspecified         = types.CreateReceiptUnspecified
	CreateReceiptPending             = types.CreateReceiptPending
	CreateReceiptSucceeded           = types.CreateReceiptSucceeded
	CreateReceiptAmbiguous           = types.CreateReceiptAmbiguous
	CreateReceiptNoResource          = types.CreateReceiptNoResource
	CreateReceiptExpired             = types.CreateReceiptExpired
	CreateReceiptNotFoundAsOfRead    = types.CreateReceiptNotFoundAsOfRead
	CreateReceiptUnsupportedCoverage = types.CreateReceiptUnsupportedCoverage
	CreateReceiptAbandoned           = types.CreateReceiptAbandoned
	CreateReceiptFencedPending       = types.CreateReceiptFencedPending
	CreateEffectUnspecified          = types.CreateEffectUnspecified
	CreateEffectNotStarted           = types.CreateEffectNotStarted
	CreateEffectResourceCommitted    = types.CreateEffectResourceCommitted
	CreateEffectDriverStarted        = types.CreateEffectDriverStarted
	CreateEffectOwnerTerminal        = types.CreateEffectOwnerTerminal
)

// CreateOwnershipClient exposes explicit receipt reads and metadata fences.
// It never sends Create, selects another target, or retries a possibly committed
// fence. Health is rechecked for each call; the server must still enforce the
// contract if its capability changes after Health and before the operation.
type CreateOwnershipClient struct{ client pb.OpenShellClient }

// CreateOwnership returns an additive client without changing legacy Sandboxes.
// The existing connection's authenticated transport is retained.
func (c *Client) CreateOwnership() *CreateOwnershipClient {
	return &CreateOwnershipClient{client: pb.NewOpenShellClient(c.conn)}
}

var ownershipUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validOwnershipUUID(value string) bool {
	return ownershipUUID.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}

func validateOwnershipKey(workspace string, key CreateOwnershipKey, expected string) error {
	if workspace == "" || workspace != strings.TrimSpace(workspace) || workspace == "*" || !validOwnershipUUID(key.RequestID) || len(key.Fingerprint) != 32 || len(key.SchemaDigest) != 64 || key.SchemaDigest != strings.ToLower(key.SchemaDigest) {
		return &StatusError{Code: ErrorInvalidArgument, Message: "named workspace and canonical original Create key required"}
	}
	if _, err := hex.DecodeString(key.SchemaDigest); err != nil {
		return &StatusError{Code: ErrorInvalidArgument, Message: "invalid fingerprint schema digest"}
	}
	if expected != "" && !validOwnershipUUID(expected) {
		return &StatusError{Code: ErrorInvalidArgument, Message: "canonical expected sandbox ID required"}
	}
	return nil
}

func (c *CreateOwnershipClient) requireCapability(ctx context.Context) error {
	response, err := c.client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	if response == nil || !slices.Contains(response.GetCapabilities(), "sandbox-create-ownership-v1") {
		return &StatusError{Code: ErrorUnimplemented, Message: "gateway lacks sandbox-create-ownership-v1; ownership RPC refused"}
	}
	return nil
}

// Get sends one SELECT-only receipt RPC after fresh capability discovery.
// Missing/expired/incomplete receipts never trigger Fence or Create.
func (c *CreateOwnershipClient) Get(ctx context.Context, workspace string, key CreateOwnershipKey, expectedSandboxID string) (*CreateOwnershipReceipt, error) {
	if err := validateOwnershipKey(workspace, key, expectedSandboxID); err != nil {
		return nil, err
	}
	// Freeze caller-owned bytes before the first network wait.
	key.Fingerprint = append([]byte(nil), key.Fingerprint...)
	if err := c.requireCapability(ctx); err != nil {
		return nil, err
	}
	request := &pb.GetSandboxCreateReceiptRequest{WorkspaceScope: namedWorkspaceScope(workspace), RequestId: key.RequestID,
		PayloadFingerprint: key.Fingerprint, FingerprintSchemaDigest: key.SchemaDigest}
	if expectedSandboxID != "" {
		request.ExpectedSandboxId = &expectedSandboxID
	}
	response, err := c.client.GetSandboxCreateReceipt(ctx, request, grpc.MaxRetryRPCBufferSize(0))
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	result, err := converter.CreateOwnershipReceiptFromProto(response, key, expectedSandboxID)
	if err != nil {
		return nil, &StatusError{Code: ErrorUnavailable, Message: "invalid Create ownership receipt", Cause: err}
	}
	return result, nil
}

// Fence is an explicit caller-authorized metadata mutation. It does not cancel
// an admitted owner and cannot prove runtime/broker absence. A lost reply is an
// error, not permission to resend; use Get for authoritative readback.
func (c *CreateOwnershipClient) Fence(ctx context.Context, workspace string, key CreateOwnershipKey) (*CreateOwnershipReceipt, error) {
	if err := validateOwnershipKey(workspace, key, ""); err != nil {
		return nil, err
	}
	key.Fingerprint = append([]byte(nil), key.Fingerprint...)
	if err := c.requireCapability(ctx); err != nil {
		return nil, err
	}
	response, err := c.client.FenceSandboxCreate(ctx, &pb.FenceSandboxCreateRequest{WorkspaceScope: namedWorkspaceScope(workspace),
		RequestId: key.RequestID, PayloadFingerprint: key.Fingerprint, FingerprintSchemaDigest: key.SchemaDigest}, grpc.MaxRetryRPCBufferSize(0))
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	result, err := converter.CreateOwnershipReceiptFromProto(response.GetReceipt(), key, "")
	if err != nil {
		return nil, &StatusError{Code: ErrorUnavailable, Message: "invalid Create ownership fence receipt", Cause: err}
	}
	if !result.AdmissionClosed || result.FenceRevision == 0 {
		return nil, &StatusError{Code: ErrorUnavailable, Message: "Create fence was not confirmed closed"}
	}
	return result, nil
}
