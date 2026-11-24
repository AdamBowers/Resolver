package securityfilter

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	policyv1 "github.com/AdamBowers/Resolver/api/policy/v1"

	"google.golang.org/protobuf/proto"
)

const (
	footerDomainSeparator = "dnsresolver.policy.v1.PolicyFooter"
	mldsaContextString    = "dnsresolver.policy.v1"
	clockSkewTolerance    = 60 * time.Second
)

// VerifierConfig controls cryptographic verification of streamed policy bundles.
type VerifierConfig struct {
	KeyringPath            string
	AllowUnsigned          bool
	RequireHybrid          bool
	StartupExpiredKeyGrace time.Duration
	Now                    func() time.Time
}

// BundleVerifier validates PolicyFooter signatures against a reloadable TrustedKeyring.
type BundleVerifier struct {
	cfg VerifierConfig
	now func() time.Time

	mu   sync.RWMutex
	keys map[string]*policyv1.TrustedKey
}

// NewBundleVerifier initializes a BundleVerifier. Fails closed if neither KeyringPath nor AllowUnsigned is set.
func NewBundleVerifier(cfg VerifierConfig) (*BundleVerifier, error) {
	if cfg.KeyringPath == "" && !cfg.AllowUnsigned {
		return nil, errors.New("securityfilter: either keyring path or allow_unsigned must be configured")
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	v := &BundleVerifier{
		cfg:  cfg,
		now:  nowFn,
		keys: make(map[string]*policyv1.TrustedKey),
	}

	if cfg.KeyringPath != "" {
		if err := v.LoadKeyring(); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// LoadKeyring reads and atomically swaps the trusted public keys from disk.
func (v *BundleVerifier) LoadKeyring() error {
	if v.cfg.KeyringPath == "" {
		return nil
	}

	raw, err := os.ReadFile(v.cfg.KeyringPath)
	if err != nil {
		return fmt.Errorf("read keyring %s: %w", v.cfg.KeyringPath, err)
	}
	if len(raw) == 0 {
		return fmt.Errorf("keyring %s is empty", v.cfg.KeyringPath)
	}

	var kr policyv1.TrustedKeyring
	if err := proto.Unmarshal(raw, &kr); err != nil {
		return fmt.Errorf("unmarshal keyring: %w", err)
	}
	if len(kr.GetKeys()) == 0 {
		return errors.New("keyring contains zero keys")
	}

	parsed := make(map[string]*policyv1.TrustedKey, len(kr.GetKeys()))
	for _, k := range kr.GetKeys() {
		if k.GetKeyId() == "" {
			return errors.New("keyring entry missing key_id")
		}
		if _, dup := parsed[k.GetKeyId()]; dup {
			return fmt.Errorf("duplicate key_id in keyring: %s", k.GetKeyId())
		}
		if err := validatePublicKeyFormat(k); err != nil {
			return fmt.Errorf("invalid key %s: %w", k.GetKeyId(), err)
		}
		parsed[k.GetKeyId()] = proto.Clone(k).(*policyv1.TrustedKey)
	}

	v.mu.Lock()
	v.keys = parsed
	v.mu.Unlock()
	return nil
}

// VerifyFooter verifies the cryptographic signatures on a PolicyFooter.
// When isStartup is true, StartupExpiredKeyGrace is applied to key expiration checks.
func (v *BundleVerifier) VerifyFooter(footer *policyv1.PolicyFooter, isStartup bool) error {
	if footer == nil {
		return errors.New("missing policy footer")
	}
	if len(footer.GetStreamSha256()) != 32 {
		return fmt.Errorf("invalid stream_sha256 length: got %d, want 32", len(footer.GetStreamSha256()))
	}

	if v.cfg.AllowUnsigned && v.cfg.KeyringPath == "" {
		return nil
	}

	sigs := footer.GetSignatures()
	if len(sigs) == 0 {
		return errors.New("policy footer contains no signatures")
	}

	msg := CanonicalFooterSigningInput(footer.GetTotalChunks(), footer.GetStreamSha256())
	now := v.now()
	grace := time.Duration(0)
	if isStartup && v.cfg.StartupExpiredKeyGrace > 0 {
		grace = v.cfg.StartupExpiredKeyGrace
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	var validClassical, validPQC int
	seenKeyIDs := make(map[string]struct{}, len(sigs))

	for _, sig := range sigs {
		keyID := sig.GetKeyId()
		if _, dup := seenKeyIDs[keyID]; dup {
			return fmt.Errorf("duplicate signature for key_id %q", keyID)
		}
		seenKeyIDs[keyID] = struct{}{}

		key, ok := v.keys[keyID]
		if !ok {
			continue
		}
		if key.GetAlgorithm() != sig.GetAlgorithm() {
			return fmt.Errorf("algorithm mismatch for key %q: key=%v sig=%v", keyID, key.GetAlgorithm(), sig.GetAlgorithm())
		}
		if err := checkKeyValidity(key, now, grace); err != nil {
			return fmt.Errorf("key %q invalid: %w", keyID, err)
		}
		if err := verifySingleSignature(key, msg, sig.GetSignature()); err != nil {
			return fmt.Errorf("signature verification failed for key %q: %w", keyID, err)
		}

		switch key.GetAlgorithm() {
		case policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519:
			validClassical++
		case policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65,
			policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_87:
			validPQC++
		}
	}

	if v.cfg.RequireHybrid {
		if validClassical == 0 || validPQC == 0 {
			return fmt.Errorf("hybrid signature requirement not met (valid classical=%d, valid pqc=%d)", validClassical, validPQC)
		}
		return nil
	}

	if validClassical+validPQC == 0 {
		return errors.New("no valid trusted signature found in policy footer")
	}
	return nil
}

// CanonicalFooterSigningInput builds the domain-separated payload signed by both classical and PQC keys.
func CanonicalFooterSigningInput(totalChunks uint64, streamSHA256 []byte) []byte {
	buf := make([]byte, 0, len(footerDomainSeparator)+1+8+len(streamSHA256))
	buf = append(buf, footerDomainSeparator...)
	buf = append(buf, 0x00)
	buf = binary.BigEndian.AppendUint64(buf, totalChunks)
	buf = append(buf, streamSHA256...)
	return buf
}

func checkKeyValidity(key *policyv1.TrustedKey, now time.Time, grace time.Duration) error {
	if key.GetRevoked() {
		return errors.New("key is revoked")
	}
	if nb := key.GetNotBefore(); nb != nil {
		if now.Add(clockSkewTolerance).Before(nb.AsTime()) {
			return fmt.Errorf("key not valid before %s", nb.AsTime().UTC().Format(time.RFC3339))
		}
	}
	if exp := key.GetExpiresAt(); exp != nil {
		deadline := exp.AsTime().Add(clockSkewTolerance + grace)
		if now.After(deadline) {
			return fmt.Errorf("key expired at %s", exp.AsTime().UTC().Format(time.RFC3339))
		}
	}
	return nil
}

func validatePublicKeyFormat(k *policyv1.TrustedKey) error {
	switch k.GetAlgorithm() {
	case policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519:
		if len(k.GetPublicKey()) != ed25519.PublicKeySize {
			return fmt.Errorf("expected %d-byte ed25519 public key, got %d", ed25519.PublicKeySize, len(k.GetPublicKey()))
		}
	case policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65:
		if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), k.GetPublicKey()); err != nil {
			return fmt.Errorf("parse ML-DSA-65 public key: %w", err)
		}
	case policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_87:
		if _, err := mldsa.NewPublicKey(mldsa.MLDSA87(), k.GetPublicKey()); err != nil {
			return fmt.Errorf("parse ML-DSA-87 public key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported signature algorithm: %v", k.GetAlgorithm())
	}
	return nil
}

func verifySingleSignature(k *policyv1.TrustedKey, msg, sig []byte) error {
	switch k.GetAlgorithm() {
	case policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519:
		if !ed25519.Verify(ed25519.PublicKey(k.GetPublicKey()), msg, sig) {
			return errors.New("ed25519 verify returned false")
		}
	case policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65:
		pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), k.GetPublicKey())
		if err != nil {
			return err
		}
		if err := mldsa.Verify(pub, msg, sig, &mldsa.Options{Context: mldsaContextString}); err != nil {
			return err
		}
	case policyv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_87:
		pub, err := mldsa.NewPublicKey(mldsa.MLDSA87(), k.GetPublicKey())
		if err != nil {
			return err
		}
		if err := mldsa.Verify(pub, msg, sig, &mldsa.Options{Context: mldsaContextString}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported algorithm: %v", k.GetAlgorithm())
	}
	return nil
}
