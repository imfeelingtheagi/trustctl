package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	kmippkg "trstctl.com/trstctl/internal/kmip"
)

const kmipDefaultAddr = ":5696"

type kmipRuntime struct {
	addr         string
	certFile     string
	keyFile      string
	clientCAFile string
	service      *kmippkg.Server
	pool         *bulkhead.Pool
	log          *slog.Logger
}

func (s *Server) configureKMIPSurface(d Deps) error {
	cfg := d.Protocols.KMIP
	if !cfg.Enabled {
		return nil
	}
	if err := errors.Join(config.Protocols{KMIP: cfg}.ValidateTenantBindings(d.ProtocolTenant)...); err != nil {
		return fmt.Errorf("server: served KMIP tenant/TLS binding: %w", err)
	}
	pool := s.bulk.Pool(bulkhead.SubsystemProtocols)
	if pool == nil {
		pool = s.bulk.Pool(bulkhead.SubsystemAPI)
	}
	if pool == nil {
		return errors.New("server: KMIP requires a protocols or API bulkhead pool")
	}
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		addr = kmipDefaultAddr
	}
	logger := s.logger
	if logger == nil {
		logger = slog.Default()
	}
	// Crypto agility here is compile-time Go interface composition, in the
	// prior-art style of crypto.Signer, JCA, OpenSSL ENGINE, and PKCS#11 handles.
	// KMIP request algorithms are parameters, not runtime provider registrations.
	s.kmip = &kmipRuntime{
		addr:         addr,
		certFile:     cfg.CertFile,
		keyFile:      cfg.KeyFile,
		clientCAFile: cfg.ClientCAFile,
		service:      kmippkg.New(firstNonEmpty(cfg.TenantID, d.ProtocolTenant), kmippkg.VerifiedClientCertAuthenticator{}, audit.NewAuditor(d.Log)),
		pool:         pool,
		log:          logger,
	}
	return nil
}

// KMIPServed reports whether the running server has the KMS-02 KMIP listener
// configured. It is a served-path wiring assertion for tests and startup logs.
func (s *Server) KMIPServed() bool { return s.kmip != nil }

// KMIPAddr returns the configured KMIP listener address, or empty when KMIP is off.
func (s *Server) KMIPAddr() string {
	if s.kmip == nil {
		return ""
	}
	return s.kmip.addr
}

// RunKMIP binds and serves the configured KMIP listener until ctx is cancelled.
func (s *Server) RunKMIP(ctx context.Context) {
	if s.kmip == nil {
		return
	}
	ln, err := net.Listen("tcp", s.kmip.addr)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("KMIP listener failed to bind", slog.String("addr", s.kmip.addr), slog.String("error", err.Error()))
		}
		return
	}
	if err := s.ServeKMIP(ctx, ln); err != nil && s.logger != nil {
		s.logger.Error("KMIP listener stopped with error", slog.String("addr", s.kmip.addr), slog.String("error", err.Error()))
	}
}

// ServeKMIP serves the configured KMIP runtime on an already-open listener. Tests
// pass an ephemeral listener; production calls RunKMIP so the configured address is
// used. The listener is always wrapped in mTLS before accepting client frames.
func (s *Server) ServeKMIP(ctx context.Context, ln net.Listener) error {
	if s.kmip == nil {
		_ = ln.Close()
		return errors.New("server: KMIP is not configured")
	}
	tlsLn, err := mtls.MutualTLSServerListenerFromFiles(ln, s.kmip.certFile, s.kmip.keyFile, s.kmip.clientCAFile)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("server: configure KMIP mTLS: %w", err)
	}
	return s.kmip.serve(ctx, tlsLn)
}

func (r *kmipRuntime) serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("kmip accept: %w", err)
		}
		if err := r.pool.Submit(func() { r.handleConn(ctx, conn) }); err != nil {
			r.log.Warn("KMIP connection rejected by bulkhead", slog.String("error", err.Error()))
			_ = conn.Close()
		}
	}
}

func (r *kmipRuntime) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	clientCertDER, err := mtls.PeerCertificateDER(conn)
	if err != nil {
		r.log.Warn("KMIP mTLS peer rejected", slog.String("error", err.Error()))
		return
	}
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, err := kmippkg.ReadFrame(conn, 1<<20)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return
			}
			r.log.Warn("KMIP frame read failed", slog.String("error", err.Error()))
			return
		}
		resp, err := r.service.HandleFrame(ctx, clientCertDER, frame)
		if err != nil {
			r.log.Warn("KMIP frame handling failed", slog.String("error", err.Error()))
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Write(resp); err != nil {
			r.log.Warn("KMIP frame write failed", slog.String("error", err.Error()))
			return
		}
	}
}

func (r *kmipRuntime) Close() {
	if r.service != nil {
		r.service.Close()
	}
}
