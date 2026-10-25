// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCreateFingerprintSharedManifest(t *testing.T) {
	data, err := os.ReadFile("../../../../proto/create_fingerprint.v1.json")
	require.NoError(t, err)
	var manifest struct {
		Digest  string `json:"fingerprint_schema_digest"`
		Vectors []struct {
			Name, Canonical, SHA256 string
			MessageType             string `json:"message_type"`
			Input                   json.RawMessage
			Unknown                 string `json:"unknown_wire_hex"`
		} `json:"vectors"`
		Numbers []struct {
			Bits      string `json:"ieee754_hex"`
			Canonical string
		} `json:"number_vectors"`
	}
	require.NoError(t, json.Unmarshal(data, &manifest))
	digest := createFingerprintSchemaDigest()
	require.Equal(t, manifest.Digest, digest)
	for _, vector := range manifest.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(vector.MessageType))
			require.NoError(t, err)
			message := dynamicpb.NewMessage(mt.Descriptor())
			require.NoError(t, protojson.Unmarshal(vector.Input, message))
			wire, err := proto.Marshal(message)
			require.NoError(t, err)
			unknown, err := hex.DecodeString(vector.Unknown)
			require.NoError(t, err)
			require.NoError(t, proto.Unmarshal(append(wire, unknown...), message))
			if vector.MessageType == "openshell.v1.CreateSandboxRequest" {
				id := message.Descriptor().Fields().ByName("request_id")
				message.Set(id, protoreflect.ValueOfString(ownerRequest))
				originalWire, err := proto.Marshal(message)
				require.NoError(t, err)
				key, err := CreateOwnershipKeyFromRequest(originalWire, manifest.Digest)
				require.NoError(t, err)
				require.Equal(t, ownerRequest, key.RequestID)
				require.Equal(t, vector.SHA256, hex.EncodeToString(key.Fingerprint))
				message.Clear(message.Descriptor().Fields().ByName("request_id"))
			}
			canonical, err := canonicalCreateJSON(message)
			require.NoError(t, err)
			require.Equal(t, vector.Canonical, string(canonical))
			hash := sha256.Sum256(canonical)
			require.Equal(t, vector.SHA256, hex.EncodeToString(hash[:]))
		})
	}
	for _, vector := range manifest.Numbers {
		t.Run(vector.Bits, func(t *testing.T) {
			bits, err := hex.DecodeString(vector.Bits)
			require.NoError(t, err)
			value := math.Float64frombits(binary.BigEndian.Uint64(bits))
			got, err := canonicalCreateNumber(value)
			require.NoError(t, err)
			require.Equal(t, vector.Canonical, got)
		})
	}
}

func TestCreateFingerprintRefusesUnrepresentableOrUnboundedInputs(t *testing.T) {
	digest := createFingerprintSchemaDigest()
	for _, input := range [][]byte{nil, {0xff}, make([]byte, 4*1024*1024+1)} {
		key, err := CreateOwnershipKeyFromRequest(input, digest)
		require.Error(t, err)
		require.Empty(t, key.Fingerprint)
	}
	for _, number := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		got, err := canonicalCreateNumber(number)
		require.Error(t, err)
		require.Empty(t, got)
		request := &pb.CreateSandboxRequest{RequestId: ownerRequest, Spec: &pb.SandboxSpec{Template: &pb.SandboxTemplate{
			Resources: &structpb.Struct{Fields: map[string]*structpb.Value{"bad": structpb.NewNumberValue(number)}},
		}}}
		wire, err := proto.Marshal(request)
		require.NoError(t, err)
		key, err := CreateOwnershipKeyFromRequest(wire, digest)
		require.Error(t, err)
		require.Empty(t, key.Fingerprint)
	}
	var nested any
	for range 130 {
		nested = []any{nested}
	}
	var out bytes.Buffer
	require.Error(t, writeCreateCanonical(&out, nested, 0))
	out.Reset()
	require.NoError(t, writeCreateCanonical(&out, map[string]any{"\ue000": "bmp", "\U00010000": "\u2028\u2029<>&\x00"}, 0))
	require.Equal(t, "{\"\U00010000\":\"\u2028\u2029<>&\\u0000\",\"\ue000\":\"bmp\"}", out.String())
}

func TestCreateFingerprintKeyFeedsActualReceiptRead(t *testing.T) {
	c, server := ownershipFixture(t)
	digest := createFingerprintSchemaDigest()
	request := &pb.CreateSandboxRequest{RequestId: ownerRequest, RequireOwnershipReceipt: true, WorkspaceScope: namedWorkspaceScope("workspace-a")}
	before := proto.Clone(request)
	wire, err := proto.Marshal(request)
	require.NoError(t, err)
	key, err := CreateOwnershipKeyFromRequest(wire, digest)
	require.NoError(t, err)
	require.True(t, proto.Equal(before, request))
	server.receipt.Fingerprint = append([]byte(nil), key.Fingerprint...)
	server.receipt.FingerprintSchemaDigest = key.SchemaDigest
	_, err = c.CreateOwnership().Get(t.Context(), "workspace-a", key, "")
	require.NoError(t, err)
	require.Equal(t, key.Fingerprint, server.get.PayloadFingerprint)
	require.Equal(t, 1, server.gets)
	require.Zero(t, server.creates)
	require.Zero(t, server.fences)
	request.RequireOwnershipReceipt = false
	wire, err = proto.Marshal(request)
	require.NoError(t, err)
	changed, err := CreateOwnershipKeyFromRequest(wire, digest)
	require.NoError(t, err)
	require.NotEqual(t, key.Fingerprint, changed.Fingerprint)
	_, err = CreateOwnershipKeyFromRequest(wire, string(makeHex('0', 64)))
	require.Error(t, err)
	_, err = CreateOwnershipKeyFromRequest(nil, digest)
	require.Error(t, err)
}
