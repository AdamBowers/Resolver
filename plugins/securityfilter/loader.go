package securityfilter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	controlv1 "github.com/AdamBowers/Resolver/api/control/v1"
	policyv1 "github.com/AdamBowers/Resolver/api/policy/v1"

	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"
)

const (
	MinSupportedPolicySchema uint32 = 1
	MaxSupportedPolicySchema uint32 = 1

	defaultReloadDutyCycle = 0.005                  // 0.5% max CPU duty cycle (5ms work per 1s)
	dutyQuantum            = 500 * time.Microsecond // Yield after ~500µs of active parsing
	defaultMaxBundleBytes  = 128 << 20              // 128 MiB hard safety cap
	maxFrameBytes          = 4 << 20                // 4 MiB max single protodelim frame
)

// ErrReloadAlreadyRunning is returned when TriggerAsyncReload is called while a reload is in progress.
var ErrReloadAlreadyRunning = errors.New("policy reload already in progress")

// LoaderConfig configures the streaming, duty-paced policy loader.
type LoaderConfig struct {
	BundlePath      string
	Verifier        *BundleVerifier
	ReloadDutyCycle float64
	MaxBundleBytes  int64
	Logger          *slog.Logger
}

// ReloadStatus captures the singleton reload state exposed via GET /policy/reload.
type ReloadStatus struct {
	State              controlv1.ReloadState
	Changed            bool
	ErrorMessage       string
	PolicyRevision     uint64
	PolicyCreatedAt    time.Time
	BundleSequence     uint64
	BundleSignedAt     time.Time
	BlockedDomainRules uint64
	BlockedCIDRRules   uint64
	BundleSHA256       string
	StartedAt          time.Time
	FinishedAt         time.Time
}

type dutyLimiter struct {
	duty       float64
	sliceStart time.Time
}

func newDutyLimiter(duty float64) *dutyLimiter {
	return &dutyLimiter{
		duty:       duty,
		sliceStart: time.Now(),
	}
}

func (d *dutyLimiter) pace(ctx context.Context) error {
	if d == nil || d.duty <= 0 || d.duty >= 1.0 {
		return ctx.Err()
	}

	busy := time.Since(d.sliceStart)
	if busy < dutyQuantum {
		return ctx.Err()
	}

	sleepFor := time.Duration(float64(busy) * ((1.0 - d.duty) / d.duty))
	timer := time.NewTimer(sleepFor)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		d.sliceStart = time.Now()
		return nil
	}
}

// PolicyLoader manages unthrottled startup loading, duty-paced async reloads, and atomic snapshot swaps.
type PolicyLoader struct {
	cfg     LoaderConfig
	logger  *slog.Logger
	current atomic.Pointer[PolicySnapshot]

	statusMu sync.RWMutex
	status   ReloadStatus

	reloadMu sync.Mutex
}

// NewPolicyLoader initializes a PolicyLoader. Fails if BundlePath or Verifier is missing.
func NewPolicyLoader(cfg LoaderConfig) (*PolicyLoader, error) {
	if cfg.BundlePath == "" {
		return nil, errors.New("securityfilter: policy_bundle path cannot be empty")
	}
	if cfg.Verifier == nil {
		return nil, errors.New("securityfilter: BundleVerifier cannot be nil")
	}
	if cfg.ReloadDutyCycle == 0 {
		cfg.ReloadDutyCycle = defaultReloadDutyCycle
	}
	if cfg.MaxBundleBytes <= 0 {
		cfg.MaxBundleBytes = defaultMaxBundleBytes
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	l := &PolicyLoader{
		cfg:    cfg,
		logger: logger,
		status: ReloadStatus{
			State: controlv1.ReloadState_RELOAD_STATE_IDLE,
		},
	}
	l.current.Store(&PolicySnapshot{LoadedAt: time.Now().UTC()})
	return l, nil
}

// Current returns the active immutable PolicySnapshot without locking.
func (l *PolicyLoader) Current() *PolicySnapshot {
	return l.current.Load()
}

// Status returns the current singleton reload status.
func (l *PolicyLoader) Status() ReloadStatus {
	l.statusMu.RLock()
	defer l.statusMu.RUnlock()
	return l.status
}

// Start performs the initial unthrottled policy load before CoreDNS binds port 53.
// If the configured bundle file does not exist or fails signature/schema checks, Start returns an error (fail-closed).
func (l *PolicyLoader) Start(ctx context.Context) error {
	now := time.Now().UTC()
	snap, _, err := l.loadFromDisk(ctx, 0, true, false)
	if err != nil {
		return err
	}

	l.statusMu.Lock()
	l.status = ReloadStatus{
		State:              controlv1.ReloadState_RELOAD_STATE_IDLE,
		Changed:            true,
		PolicyRevision:     snap.PolicyRevision,
		PolicyCreatedAt:    snap.PolicyCreatedAt,
		BundleSequence:     snap.BundleSequence,
		BundleSignedAt:     snap.BundleSignedAt,
		BlockedDomainRules: snap.BlockedDomainCount,
		BlockedCIDRRules:   snap.BlockedCIDRCount,
		BundleSHA256:       snap.BundleSHA256,
		StartedAt:          now,
		FinishedAt:         time.Now().UTC(),
	}
	l.statusMu.Unlock()
	return nil
}

// TriggerAsyncReload starts a single background duty-paced reload if one is not already running.
// Returns (startedAt, nil) on success, or (startedAt, ErrReloadAlreadyRunning) if already in progress.
func (l *PolicyLoader) TriggerAsyncReload(ctx context.Context, reloadKeyring bool) (time.Time, error) {
	l.statusMu.Lock()
	if l.status.State == controlv1.ReloadState_RELOAD_STATE_RUNNING {
		started := l.status.StartedAt
		l.statusMu.Unlock()
		return started, ErrReloadAlreadyRunning
	}

	started := time.Now().UTC()
	l.status = ReloadStatus{
		State:     controlv1.ReloadState_RELOAD_STATE_RUNNING,
		StartedAt: started,
	}
	l.statusMu.Unlock()

	go l.runAsyncReload(ctx, started, reloadKeyring)
	return started, nil
}

func (l *PolicyLoader) runAsyncReload(ctx context.Context, started time.Time, reloadKeyring bool) {
	snap, changed, err := l.loadFromDisk(ctx, l.cfg.ReloadDutyCycle, false, reloadKeyring)
	finished := time.Now().UTC()

	l.statusMu.Lock()
	defer l.statusMu.Unlock()

	if err != nil {
		l.logger.Error("async policy reload failed", "error", err)
		l.status = ReloadStatus{
			State:        controlv1.ReloadState_RELOAD_STATE_FAILED,
			ErrorMessage: err.Error(),
			StartedAt:    started,
			FinishedAt:   finished,
		}
		return
	}

	l.status = ReloadStatus{
		State:              controlv1.ReloadState_RELOAD_STATE_SUCCEEDED,
		Changed:            changed,
		PolicyRevision:     snap.PolicyRevision,
		PolicyCreatedAt:    snap.PolicyCreatedAt,
		BundleSequence:     snap.BundleSequence,
		BundleSignedAt:     snap.BundleSignedAt,
		BlockedDomainRules: snap.BlockedDomainCount,
		BlockedCIDRRules:   snap.BlockedCIDRCount,
		BundleSHA256:       snap.BundleSHA256,
		StartedAt:          started,
		FinishedAt:         finished,
	}
}

func (l *PolicyLoader) loadFromDisk(
	ctx context.Context,
	duty float64,
	isStartup bool,
	reloadKeyring bool,
) (*PolicySnapshot, bool, error) {
	l.reloadMu.Lock()
	defer l.reloadMu.Unlock()

	if reloadKeyring {
		if err := l.cfg.Verifier.LoadKeyring(); err != nil {
			return nil, false, fmt.Errorf("reload keyring: %w", err)
		}
	}

	info, err := os.Stat(l.cfg.BundlePath)
	if err != nil {
		// Fail-closed: configured policy bundle file MUST exist
		return nil, false, fmt.Errorf("stat policy bundle %s: %w", l.cfg.BundlePath, err)
	}
	if info.IsDir() {
		return nil, false, fmt.Errorf("policy bundle %s is a directory, expected regular file", l.cfg.BundlePath)
	}
	if info.Size() > l.cfg.MaxBundleBytes {
		return nil, false, fmt.Errorf("policy bundle size %d exceeds max %d bytes", info.Size(), l.cfg.MaxBundleBytes)
	}

	prev := l.Current()

	// 0-byte sentinel file -> explicit pass-through policy (no rules)
	if info.Size() == 0 {
		if !isStartup && prev.BundleSHA256 == "" && prev.BlockedDomains == nil && prev.BlockedIPs == nil {
			return prev, false, nil
		}
		next := &PolicySnapshot{
			LoadedAt: time.Now().UTC(),
		}
		l.current.Store(next)
		l.logger.Info("loaded empty policy bundle (pass-through mode)")
		return next, true, nil
	}

	f, err := os.Open(l.cfg.BundlePath)
	if err != nil {
		return nil, false, fmt.Errorf("open policy bundle: %w", err)
	}
	defer f.Close()

	fullHasher := sha256.New()
	streamHasher := sha256.New()
	bufReader := bufio.NewReaderSize(io.TeeReader(f, fullHasher), 64<<10)

	unmarshaler := protodelim.UnmarshalOptions{
		MaxSize: maxFrameBytes,
	}

	// Frame 1: PolicyHeader
	var headerFrame policyv1.PolicyFrame
	if err := readHashedFrame(bufReader, streamHasher, unmarshaler, &headerFrame); err != nil {
		return nil, false, fmt.Errorf("read policy header frame: %w", err)
	}
	hdr := headerFrame.GetHeader()
	if hdr == nil {
		return nil, false, errors.New("first frame in policy bundle is not PolicyHeader")
	}
	if hdr.GetSchemaVersion() < MinSupportedPolicySchema || hdr.GetSchemaVersion() > MaxSupportedPolicySchema {
		return nil, false, fmt.Errorf(
			"unsupported policy schema_version %d (supported: %d..%d)",
			hdr.GetSchemaVersion(), MinSupportedPolicySchema, MaxSupportedPolicySchema,
		)
	}
	if !isStartup && hdr.GetBundleSequence() < prev.BundleSequence {
		return nil, false, fmt.Errorf(
			"anti-rollback: incoming bundle_sequence %d < active %d",
			hdr.GetBundleSequence(), prev.BundleSequence,
		)
	}

	// Fast-path: identical policy_revision already loaded (e.g., key-rotation re-sign)
	samePolicyRevision := !isStartup &&
		prev.PolicyRevision > 0 &&
		hdr.GetPolicyRevision() == prev.PolicyRevision

	var domTree *DomainTree
	var ipTree *IPRadixTree
	if !samePolicyRevision {
		domTree = NewDomainTree()
		ipTree = NewIPRadixTree()
	}

	limiter := newDutyLimiter(duty)
	var expectedSeq uint64 = 1
	var footer *policyv1.PolicyFooter
	var chunkFrame policyv1.PolicyFrame

	for {
		if err := limiter.pace(ctx); err != nil {
			return nil, false, err
		}

		var rawFrame bytes.Buffer
		if err := captureRawDelimitedFrame(bufReader, &rawFrame); err != nil {
			return nil, false, fmt.Errorf("read frame after chunk %d: %w", expectedSeq-1, err)
		}

		proto.Reset(&chunkFrame)
		if err := unmarshaler.UnmarshalFrom(bytes.NewReader(rawFrame.Bytes()), &chunkFrame); err != nil {
			return nil, false, fmt.Errorf("unmarshal frame after chunk %d: %w", expectedSeq-1, err)
		}

		if ftr := chunkFrame.GetFooter(); ftr != nil {
			footer = ftr
			break
		}

		// Not footer -> include frame bytes in streamHasher before processing chunk
		streamHasher.Write(rawFrame.Bytes())
		chk := chunkFrame.GetChunk()
		if chk == nil {
			return nil, false, fmt.Errorf("unexpected frame type at sequence %d", expectedSeq)
		}
		if chk.GetSequence() != expectedSeq {
			return nil, false, fmt.Errorf("chunk sequence mismatch: got %d, want %d", chk.GetSequence(), expectedSeq)
		}
		expectedSeq++
		if samePolicyRevision {
			continue
		}
		for _, dom := range chk.GetBlockedDomains() {
			if err := domTree.Insert(dom); err != nil {
				l.logger.Warn("skipping invalid blocked domain in bundle", "domain", dom, "error", err)
			}
		}
		for _, cidr := range chk.GetBlockedIps() {
			pfx, err := protoToPrefix(cidr)
			if err != nil {
				l.logger.Warn("skipping invalid blocked CIDR in bundle", "error", err)
				continue
			}
			ipTree.InsertPrefix(pfx)
		}
	}
	// Ensure no trailing garbage exists after PolicyFooter
	if _, err := bufReader.Peek(1); !errors.Is(err, io.EOF) {
		return nil, false, errors.New("unexpected trailing bytes after PolicyFooter")
	}
	actualChunkCount := expectedSeq - 1
	if footer.GetTotalChunks() != actualChunkCount {
		return nil, false, fmt.Errorf("chunk count mismatch: footer=%d, read=%d", footer.GetTotalChunks(), actualChunkCount)
	}
	computedStreamSHA := streamHasher.Sum(nil)
	if !bytes.Equal(computedStreamSHA, footer.GetStreamSha256()) {
		return nil, false, errors.New("stream_sha256 digest mismatch between streamed frames and PolicyFooter")
	}
	// Cryptographic verification MUST succeed before swapping PolicySnapshot
	if err := l.cfg.Verifier.VerifyFooter(footer, isStartup); err != nil {
		return nil, false, fmt.Errorf("policy signature verification failed: %w", err)
	}
	fullBundleHex := hex.EncodeToString(fullHasher.Sum(nil))
	if !isStartup && fullBundleHex == prev.BundleSHA256 {
		return prev, false, nil
	}
	var policyCreatedAt, bundleSignedAt time.Time
	if ts := hdr.GetPolicyCreatedAt(); ts != nil {
		policyCreatedAt = ts.AsTime().UTC()
	}
	if ts := hdr.GetBundleSignedAt(); ts != nil {
		bundleSignedAt = ts.AsTime().UTC()
	}
	if samePolicyRevision {
		domTree = prev.BlockedDomains
		ipTree = prev.BlockedIPs
	} else {
		if domTree.Count() == 0 {
			domTree = nil
		}
		if ipTree.Count() == 0 {
			ipTree = nil
		}
	}
	next := &PolicySnapshot{
		BlockedDomains:     domTree,
		BlockedIPs:         ipTree,
		BlockedDomainCount: uint64(domTree.Count()),
		BlockedCIDRCount:   uint64(ipTree.Count()),
		PolicyRevision:     hdr.GetPolicyRevision(),
		PolicyCreatedAt:    policyCreatedAt,
		BundleSequence:     hdr.GetBundleSequence(),
		BundleSignedAt:     bundleSignedAt,
		BundleSHA256:       fullBundleHex,
		LoadedAt:           time.Now().UTC(),
	}
	l.current.Store(next)
	l.logger.Info("policy snapshot activated",
		"policy_revision", next.PolicyRevision,
		"bundle_sequence", next.BundleSequence,
		"blocked_domains", next.BlockedDomainCount,
		"blocked_cidrs", next.BlockedCIDRCount,
		"reused_trees", samePolicyRevision,
	)
	return next, true, nil
}
func readHashedFrame(
	r *bufio.Reader,
	h hash.Hash,
	u protodelim.UnmarshalOptions,
	dst proto.Message,
) error {
	var raw bytes.Buffer
	if err := captureRawDelimitedFrame(r, &raw); err != nil {
		return err
	}
	h.Write(raw.Bytes())
	return u.UnmarshalFrom(bytes.NewReader(raw.Bytes()), dst)
}
func captureRawDelimitedFrame(r *bufio.Reader, dst *bytes.Buffer) error {
	var size uint64
	var shift uint
	for i := 0; i < 10; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		dst.WriteByte(b)
		size |= uint64(b&0x7f) << shift
		if b < 0x80 {
			break
		}
		shift += 7
		if i == 9 {
			return errors.New("varint length overflow")
		}
	}
	if size > maxFrameBytes {
		return fmt.Errorf("frame size %d exceeds maxFrameBytes %d", size, maxFrameBytes)
	}
	if size == 0 {
		return nil
	}
	dst.Grow(int(size))
	if _, err := io.CopyN(dst, r, int64(size)); err != nil {
		return err
	}
	return nil
}
func protoToPrefix(c *policyv1.CIDRPrefix) (netip.Prefix, error) {
	if c == nil {
		return netip.Prefix{}, errors.New("nil CIDRPrefix")
	}
	addr, ok := netip.AddrFromSlice(c.GetAddr())
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid IP byte length: %d", len(c.GetAddr()))
	}
	bits := int(c.GetPrefixLen())
	if bits < 0 || bits > addr.BitLen() {
		return netip.Prefix{}, fmt.Errorf("prefix_len %d out of range for %d-bit address", bits, addr.BitLen())
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}
