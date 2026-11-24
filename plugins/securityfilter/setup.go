package securityfilter

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	plugin.Register("securityfilter", setup)
}

func setup(c *caddy.Controller) error {
	sf, err := parseSecurityFilter(c)
	if err != nil {
		return plugin.Error("securityfilter", err)
	}

	c.OnStartup(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Fail-closed: load & verify policy.pb synchronously before accepting DNS traffic.
		if err := sf.loader.Start(ctx); err != nil {
			return fmt.Errorf("securityfilter initial policy load: %w", err)
		}
		if err := sf.control.Start(); err != nil {
			return fmt.Errorf("securityfilter control socket start: %w", err)
		}
		return nil
	})

	c.OnShutdown(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var errs []error
		if sf.control != nil {
			if err := sf.control.Stop(ctx); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("securityfilter shutdown errors: %v", errs)
		}
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		sf.Next = next
		return sf
	})

	return nil
}

func parseSecurityFilter(c *caddy.Controller) (*SecurityFilter, error) {
	var (
		bundlePath      string
		socketPath      string
		keyringPath     string
		allowUnsigned   bool
		requireHybrid   = true
		startupKeyGrace time.Duration
		maxBundleMB     int64 = 128
		reloadDutyCycle       = defaultReloadDutyCycle
	)

	for c.Next() {
		if c.NextArg() {
			return nil, c.ArgErr()
		}
		for c.NextBlock() {
			switch c.Val() {
			case "policy_bundle":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				bundlePath = c.Val()
				if c.NextArg() {
					return nil, c.ArgErr()
				}

			case "control_socket":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				socketPath = c.Val()
				if c.NextArg() {
					return nil, c.ArgErr()
				}

			case "keyring":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				keyringPath = c.Val()
				if c.NextArg() {
					return nil, c.ArgErr()
				}

			case "allow_unsigned":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				v, err := strconv.ParseBool(c.Val())
				if err != nil {
					return nil, fmt.Errorf("invalid allow_unsigned %q: %w", c.Val(), err)
				}
				allowUnsigned = v
				if c.NextArg() {
					return nil, c.ArgErr()
				}

			case "require_hybrid":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				v, err := strconv.ParseBool(c.Val())
				if err != nil {
					return nil, fmt.Errorf("invalid require_hybrid %q: %w", c.Val(), err)
				}
				requireHybrid = v
				if c.NextArg() {
					return nil, c.ArgErr()
				}

			case "startup_expired_key_grace":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				d, err := time.ParseDuration(c.Val())
				if err != nil {
					return nil, fmt.Errorf("invalid startup_expired_key_grace %q: %w", c.Val(), err)
				}
				startupKeyGrace = d
				if c.NextArg() {
					return nil, c.ArgErr()
				}

			case "max_bundle_mb":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				mb, err := strconv.ParseInt(c.Val(), 10, 64)
				if err != nil || mb <= 0 {
					return nil, fmt.Errorf("invalid max_bundle_mb %q", c.Val())
				}
				maxBundleMB = mb
				if c.NextArg() {
					return nil, c.ArgErr()
				}

			case "reload_duty_cycle":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				dc, err := strconv.ParseFloat(c.Val(), 64)
				if err != nil || dc <= 0 || dc >= 1.0 {
					return nil, fmt.Errorf("invalid reload_duty_cycle %q (must be > 0 and < 1)", c.Val())
				}
				reloadDutyCycle = dc
				if c.NextArg() {
					return nil, c.ArgErr()
				}

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	logger := slog.Default()

	verifier, err := NewBundleVerifier(VerifierConfig{
		KeyringPath:            keyringPath,
		AllowUnsigned:          allowUnsigned,
		RequireHybrid:          requireHybrid,
		StartupExpiredKeyGrace: startupKeyGrace,
	})
	if err != nil {
		return nil, err
	}

	loader, err := NewPolicyLoader(LoaderConfig{
		BundlePath:      bundlePath,
		Verifier:        verifier,
		ReloadDutyCycle: reloadDutyCycle,
		MaxBundleBytes:  maxBundleMB << 20,
		Logger:          logger,
	})
	if err != nil {
		return nil, err
	}

	control := NewControlServer(socketPath, loader, logger)

	sf := &SecurityFilter{
		loader:  loader,
		control: control,
	}

	return sf, nil
}
