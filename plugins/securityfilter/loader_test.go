package securityfilter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/AdamBowers/Resolver/api/control/v1"
	policyv1 "github.com/AdamBowers/Resolver/api/policy/v1"

	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type testHybridKeys struct {
	edKeyID    string
	edPub      ed25519.PublicKey
	edPriv     ed25519.PrivateKey
	pqcKeyID   string
	pqcPriv    *mldsa.PrivateKey
	pqcPubByte []byte
}

func generateTestHybridKeys(t *testing.T, prefix string) testHybridKeys {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pqcPriv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	return testHybridKeys{
		edKeyID:    prefix + "-ed25519",
		edPub:      edPub,
		edPriv:     edPriv,
		pqcKeyID:   prefix + "-mldsa65",
		pqcPriv:    pqcPriv,
		pqcPubByte: pqcPriv.PublicKey().Bytes(),
	}
}

func writeTestKeyring(t *testing.T, path string, entries []*policyv1.TrustedKey) {
	t.Helper()
	raw, err := proto.Marshal(&policyv1.TrustedKeyring{
		KeyringVersion: 1,
		Keys:           entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeStreamedBundle(
	t *testing.T,
	path string,
	hdr *policyv1.PolicyHeader,
	domains []string,
	cidrs []netip.Prefix,
	chunkSize int,
	signers []testHybridKeys,
) {
	t.Helper()
	var buf bytes.Buffer
	streamHash := sha256.New()
	mw := io.MultiWriter(&buf, streamHash)

	if _, err := protodelim.MarshalTo(mw, &policyv1.PolicyFrame{
		Frame: &policyv1.PolicyFrame_Header{Header: hdr},
	}); err != nil {
		t.Fatal(err)
	}

	var seq uint64
	for len(domains) > 0 || len(cidrs) > 0 {
		seq++
		var domBatch []string
		if len(domains) > 0 {
			n := min(chunkSize, len(domains))
			domBatch = domains[:n]
			domains = domains[n:]
		}
		var cidrBatch []*policyv1.CIDRPrefix
		if len(cidrs) > 0 {
			n := min(chunkSize, len(cidrs))
			for _, p := range cidrs[:n] {
				cidrBatch = append(cidrBatch, &policyv1.CIDRPrefix{
					Addr:      p.Addr().AsSlice(),
					PrefixLen: uint32(p.Bits()),
				})
			}
			cidrs = cidrs[n:]
		}

		if _, err := protodelim.MarshalTo(mw, &policyv1.PolicyFrame{
			Frame: &policyv1.PolicyFrame_Chunk{
				Chunk: &policyv1.PolicyChunk{
					Sequence:       seq,
					BlockedDomains: domBatch,
					BlockedIps:     cidrBatch,
				},
			},
		}); err != nil {
			t.Fatal(err)
		}
	}

	digest := streamHash.Sum(nil)
	msg := CanonicalFooterSigningInput(seq, digest)

	var sigs []*policyv1.Signature
	for _, s := range signers {
		edSig := ed25519.Sign(s.edPriv, msg)
		pqcSig, err := s.pqcPriv.Sign(rand.Reader, msg, &mldsa.Options{Context: mldsaContextString})
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs,
			&policyv1.Signature{
				KeyId:     s.edKeyID,
				Algorithm: policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
				Signature: edSig,
			},
			&policyv1.Signature{
				KeyId:     s.pqcKeyID,
				Algorithm: policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65,
				Signature: pqcSig,
			},
		)
	}

	if _, err := protodelim.MarshalTo(&buf, &policyv1.PolicyFrame{
		Frame: &policyv1.PolicyFrame_Footer{
			Footer: &policyv1.PolicyFooter{
				TotalChunks:  seq,
				StreamSha256: digest,
				Signatures:   sigs,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func udsHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

func TestPolicyLoader_FailClosedAndUnsignedDevMode(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "policy.pb")

	verifier, err := NewBundleVerifier(VerifierConfig{
		AllowUnsigned: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	loader, err := NewPolicyLoader(LoaderConfig{
		BundlePath: bundlePath,
		Verifier:   verifier,
		Logger:     quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Missing file MUST fail startup
	if err := loader.Start(t.Context()); err == nil {
		t.Fatal("expected Start() to fail when policy.pb is missing")
	}

	// 2. Empty 0-byte file MUST succeed as pass-through
	if err := os.WriteFile(bundlePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loader.Start(t.Context()); err != nil {
		t.Fatalf("expected Start() to succeed on 0-byte file, got: %v", err)
	}
	if snap := loader.Current(); snap.BlockedDomains != nil || snap.BlockedIPs != nil {
		t.Fatal("expected nil trees for 0-byte pass-through bundle")
	}
}

func TestHybridPQC_KeyRotationAndExpiry(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "trusted-keyring.pb")
	bundlePath := filepath.Join(dir, "policy.pb")

	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	k1 := generateTestHybridKeys(t, "rot1")
	k2 := generateTestHybridKeys(t, "rot2")

	// Keyring contains both rot1 (expires in 1h) and rot2 (expires in 30d)
	writeTestKeyring(t, keyringPath, []*policyv1.TrustedKey{
		{
			KeyId:     k1.edKeyID,
			Algorithm: policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
			PublicKey: k1.edPub,
			ExpiresAt: timestamppb.New(now.Add(1 * time.Hour)),
		},
		{
			KeyId:     k1.pqcKeyID,
			Algorithm: policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65,
			PublicKey: k1.pqcPubByte,
			ExpiresAt: timestamppb.New(now.Add(1 * time.Hour)),
		},
		{
			KeyId:     k2.edKeyID,
			Algorithm: policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
			PublicKey: k2.edPub,
			ExpiresAt: timestamppb.New(now.Add(30 * 24 * time.Hour)),
		},
		{
			KeyId:     k2.pqcKeyID,
			Algorithm: policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65,
			PublicKey: k2.pqcPubByte,
			ExpiresAt: timestamppb.New(now.Add(30 * 24 * time.Hour)),
		},
	})

	currentTime := now
	verifier, err := NewBundleVerifier(VerifierConfig{
		KeyringPath:   keyringPath,
		RequireHybrid: true,
		Now:           func() time.Time { return currentTime },
	})
	if err != nil {
		t.Fatal(err)
	}

	// Write bundle signed with k1
	hdr := &policyv1.PolicyHeader{
		SchemaVersion:   1,
		PolicyRevision:  10,
		PolicyCreatedAt: timestamppb.New(now),
		BundleSequence:  100,
		BundleSignedAt:  timestamppb.New(now),
	}
	writeStreamedBundle(t, bundlePath, hdr, []string{"malware.test"}, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, 250, []testHybridKeys{k1})

	loader, err := NewPolicyLoader(LoaderConfig{
		BundlePath:      bundlePath,
		Verifier:        verifier,
		ReloadDutyCycle: -1, // disable delay for fast unit test
		Logger:          quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := loader.Start(t.Context()); err != nil {
		t.Fatalf("Start with k1 failed: %v", err)
	}

	// Advance clock past k1 expiry -> reload of k1-signed bundle MUST fail
	currentTime = now.Add(2 * time.Hour)
	if _, _, err := loader.loadFromDisk(t.Context(), 0, false, false); err == nil {
		t.Fatal("expected reload with expired k1 key to fail")
	}

	// Re-sign same policy_revision 10 with k2 (bundle_sequence 101) -> fast-path succeeds
	hdrResign := &policyv1.PolicyHeader{
		SchemaVersion:   1,
		PolicyRevision:  10,
		PolicyCreatedAt: timestamppb.New(now),
		BundleSequence:  101,
		BundleSignedAt:  timestamppb.New(currentTime),
	}
	writeStreamedBundle(t, bundlePath, hdrResign, []string{"malware.test"}, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, 250, []testHybridKeys{k2})

	snap, changed, err := loader.loadFromDisk(t.Context(), 0, false, false)
	if err != nil || !changed {
		t.Fatalf("expected re-signed k2 reload to succeed, changed=%v err=%v", changed, err)
	}
	if snap.PolicyRevision != 10 || snap.BundleSequence != 101 {
		t.Fatalf("unexpected snapshot revisions: %+v", snap)
	}
}

func TestControlServer_AsyncReloadAndConflict(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "policy.pb")
	sockPath := filepath.Join(dir, "control.sock")

	verifier, err := NewBundleVerifier(VerifierConfig{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}

	// Initial empty policy
	if err := os.WriteFile(bundlePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	loader, err := NewPolicyLoader(LoaderConfig{
		BundlePath:      bundlePath,
		Verifier:        verifier,
		ReloadDutyCycle: 0.05, // 5% duty cycle so async reload stays RUNNING long enough to test 409 Conflict
		Logger:          quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	cs := NewControlServer(sockPath, loader, quietLogger())
	if err := cs.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Stop(context.Background()) }()

	client := udsHTTPClient(sockPath)

	// Write a multi-chunk bundle so duty pacing keeps reload active briefly
	var domains []string
	for i := 0; i < 3000; i++ {
		domains = append(domains, fmt.Sprintf("evil-%d.test", i))
	}
	now := time.Now().UTC()
	writeStreamedBundle(t, bundlePath, &policyv1.PolicyHeader{
		SchemaVersion:   1,
		PolicyRevision:  42,
		PolicyCreatedAt: timestamppb.New(now),
		BundleSequence:  42,
		BundleSignedAt:  timestamppb.New(now),
	}, domains, nil, 250, nil)

	// Trigger POST /policy/reload -> 202 Accepted
	reqBody, _ := proto.Marshal(&controlv1.ReloadPolicyRequest{
		ClientControlVersion:   1,
		ExpectedPolicyRevision: 42,
	})
	resp, err := client.Post("http://unix/policy/reload", protobufContentType, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d", resp.StatusCode)
	}
	// Concurrent second POST /policy/reload -> 409 Conflict
	resp2, err := client.Post("http://unix/policy/reload", protobufContentType, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict while reload running, got %d", resp2.StatusCode)
	}
	// Poll GET /policy/reload until SUCCEEDED
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stResp, err := client.Get("http://unix/policy/reload")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(stResp.Body)
		stResp.Body.Close()
		var st controlv1.ReloadStatusResponse
		if err := proto.Unmarshal(raw, &st); err != nil {
			t.Fatal(err)
		}
		if st.GetState() == controlv1.ReloadState_RELOAD_STATE_SUCCEEDED {
			if st.GetPolicyRevision() != 42 || st.GetBlockedDomainRules() != 3000 {
				t.Fatalf("unexpected reload status: %+v", &st)
			}
			break
		}
		if st.GetState() == controlv1.ReloadState_RELOAD_STATE_FAILED {
			t.Fatalf("reload failed unexpectedly: %s", st.GetErrorMessage())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Verify GET /policy reflects active snapshot
	polResp, err := client.Get("http://unix/policy")
	if err != nil {
		t.Fatal(err)
	}
	polRaw, _ := io.ReadAll(polResp.Body)
	polResp.Body.Close()
	var active controlv1.GetPolicyResponse
	if err := proto.Unmarshal(polRaw, &active); err != nil {
		t.Fatal(err)
	}
	if active.GetPolicyRevision() != 42 || active.GetBlockedDomainRules() != 3000 {
		t.Fatalf("unexpected GET /policy response: %+v", &active)
	}
}
func TestPolicyLoader_ConcurrentHotPathReads(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "policy.pb")
	verifier, _ := NewBundleVerifier(VerifierConfig{AllowUnsigned: true})
	now := time.Now().UTC()
	writeStreamedBundle(t, bundlePath, &policyv1.PolicyHeader{
		SchemaVersion:   1,
		PolicyRevision:  1,
		PolicyCreatedAt: timestamppb.New(now),
		BundleSequence:  1,
		BundleSignedAt:  timestamppb.New(now),
	}, []string{"block.test"}, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, 250, nil)
	loader, err := NewPolicyLoader(LoaderConfig{
		BundlePath:      bundlePath,
		Verifier:        verifier,
		ReloadDutyCycle: -1,
		Logger:          quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.MustParseAddr("203.0.113.5")
			for !stop.Load() {
				snap := loader.Current()
				if snap.BlockedDomains != nil {
					_ = snap.BlockedDomains.Match("sub.block.test.")
				}
				if snap.BlockedIPs != nil {
					_ = snap.BlockedIPs.Contains(ip)
				}
			}
		}()
	}
	for seq := uint64(2); seq <= 6; seq++ {
		writeStreamedBundle(t, bundlePath, &policyv1.PolicyHeader{
			SchemaVersion:   1,
			PolicyRevision:  seq,
			PolicyCreatedAt: timestamppb.New(now),
			BundleSequence:  seq,
			BundleSignedAt:  timestamppb.New(now),
		}, []string{"block.test", fmt.Sprintf("extra-%d.test", seq)}, nil, 250, nil)
		if _, _, err := loader.loadFromDisk(t.Context(), 0, false, false); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
}
