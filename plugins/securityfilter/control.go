package securityfilter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	controlv1 "github.com/AdamBowers/Resolver/api/control/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	ControlProtocolVersion uint32 = 1
	protobufContentType           = "application/x-protobuf"
	maxControlBodyBytes           = 64 << 10 // 64 KiB
)

// ControlServer exposes Protobuf-over-HTTP endpoints on a Unix Domain Socket.
type ControlServer struct {
	socketPath string
	loader     *PolicyLoader
	logger     *slog.Logger
	listener   net.Listener
	server     *http.Server
}

// NewControlServer initializes the UDS control server with /policy, /policy/reload, and /healthz routes.
func NewControlServer(socketPath string, loader *PolicyLoader, logger *slog.Logger) *ControlServer {
	if logger == nil {
		logger = slog.Default()
	}

	cs := &ControlServer{
		socketPath: socketPath,
		loader:     loader,
		logger:     logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /policy", cs.handleGetPolicy)
	mux.HandleFunc("POST /policy/reload", cs.handlePostPolicyReload)
	mux.HandleFunc("GET /policy/reload", cs.handleGetPolicyReloadStatus)
	mux.HandleFunc("GET /healthz", cs.handleHealthz)

	cs.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	return cs
}

// Start binds the Unix Domain Socket and begins serving requests.
func (cs *ControlServer) Start() error {
	if cs.socketPath == "" {
		return errors.New("control socket path cannot be empty")
	}

	if err := os.MkdirAll(filepath.Dir(cs.socketPath), 0o750); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	if err := os.Remove(cs.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale control socket: %w", err)
	}

	ln, err := net.Listen("unix", cs.socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", cs.socketPath, err)
	}

	if err := os.Chmod(cs.socketPath, 0o660); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod control socket: %w", err)
	}

	cs.listener = ln
	cs.logger.Info("control socket listening", "socket", cs.socketPath)

	go func() {
		if err := cs.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cs.logger.Error("control socket server exited unexpectedly", "error", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the control server and removes the socket inode.
func (cs *ControlServer) Stop(ctx context.Context) error {
	var err error
	if cs.server != nil {
		err = cs.server.Shutdown(ctx)
	}
	if cs.socketPath != "" {
		_ = os.Remove(cs.socketPath)
	}
	return err
}

func (cs *ControlServer) handleGetPolicy(w http.ResponseWriter, _ *http.Request) {
	snap := cs.loader.Current()
	resp := &controlv1.GetPolicyResponse{
		ControlProtocolVersion: ControlProtocolVersion,
		MinPolicySchema:        MinSupportedPolicySchema,
		MaxPolicySchema:        MaxSupportedPolicySchema,
		PolicyRevision:         snap.PolicyRevision,
		PolicyCreatedAt:        toProtoTimestamp(snap.PolicyCreatedAt),
		BundleSequence:         snap.BundleSequence,
		BundleSignedAt:         toProtoTimestamp(snap.BundleSignedAt),
		BlockedDomainRules:     snap.BlockedDomainCount,
		BlockedCidrRules:       snap.BlockedCIDRCount,
		BundleSha256:           snap.BundleSHA256,
		LoadedAt:               toProtoTimestamp(snap.LoadedAt),
	}
	writeProto(w, http.StatusOK, resp)
}

func (cs *ControlServer) handlePostPolicyReload(w http.ResponseWriter, r *http.Request) {
	var req controlv1.ReloadPolicyRequest
	if r.Body != nil {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxControlBodyBytes))
		if err != nil {
			http.Error(w, "failed reading request body", http.StatusBadRequest)
			return
		}
		if len(raw) > 0 {
			if err := proto.Unmarshal(raw, &req); err != nil {
				http.Error(w, "invalid protobuf ReloadPolicyRequest", http.StatusBadRequest)
				return
			}
		}
	}

	startedAt, err := cs.loader.TriggerAsyncReload(context.Background(), req.GetReloadKeyring())
	if errors.Is(err, ErrReloadAlreadyRunning) {
		writeProto(w, http.StatusConflict, &controlv1.ReloadPolicyResponse{
			State:                  controlv1.ReloadState_RELOAD_STATE_RUNNING,
			ControlProtocolVersion: ControlProtocolVersion,
			MinPolicySchema:        MinSupportedPolicySchema,
			MaxPolicySchema:        MaxSupportedPolicySchema,
			StartedAt:              toProtoTimestamp(startedAt),
		})
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeProto(w, http.StatusAccepted, &controlv1.ReloadPolicyResponse{
		State:                  controlv1.ReloadState_RELOAD_STATE_RUNNING,
		ControlProtocolVersion: ControlProtocolVersion,
		MinPolicySchema:        MinSupportedPolicySchema,
		MaxPolicySchema:        MaxSupportedPolicySchema,
		StartedAt:              toProtoTimestamp(startedAt),
	})
}

func (cs *ControlServer) handleGetPolicyReloadStatus(w http.ResponseWriter, _ *http.Request) {
	st := cs.loader.Status()
	resp := &controlv1.ReloadStatusResponse{
		State:              st.State,
		Changed:            st.Changed,
		ErrorMessage:       st.ErrorMessage,
		PolicyRevision:     st.PolicyRevision,
		PolicyCreatedAt:    toProtoTimestamp(st.PolicyCreatedAt),
		BundleSequence:     st.BundleSequence,
		BundleSignedAt:     toProtoTimestamp(st.BundleSignedAt),
		BlockedDomainRules: st.BlockedDomainRules,
		BlockedCidrRules:   st.BlockedCIDRRules,
		BundleSha256:       st.BundleSHA256,
		StartedAt:          toProtoTimestamp(st.StartedAt),
		FinishedAt:         toProtoTimestamp(st.FinishedAt),
	}
	writeProto(w, http.StatusOK, resp)
}

func (cs *ControlServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	st := cs.loader.Status()
	resp := &controlv1.HealthResponse{
		Healthy:                true,
		ControlProtocolVersion: ControlProtocolVersion,
		ReloadState:            st.State,
		LastReloadError:        st.ErrorMessage,
	}
	writeProto(w, http.StatusOK, resp)
}

func writeProto(w http.ResponseWriter, status int, msg proto.Message) {
	out, err := proto.Marshal(msg)
	if err != nil {
		http.Error(w, "marshal protobuf response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", protobufContentType)
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

func toProtoTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
