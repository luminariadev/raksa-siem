package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-siem/internal/normalizer"
)

const (
	maxSyslogUDPPacketBytes = 64 * 1024
	maxSyslogTCPLineBytes   = 256 * 1024
	maxSyslogTCPConns       = 128
	syslogTCPIdleTimeout    = 60 * time.Second
)

// StartSyslog launches optional UDP and TCP RFC 3164/5424 syslog listeners alongside the HTTP server.
// Returned shutdown function stops listeners and waits for active handlers to drain.
func (s *Server) StartSyslog(ctx context.Context) (func(), error) {
	var wg sync.WaitGroup
	var closers []func()

	cleanup := func() {
		for _, fn := range closers {
			fn()
		}
		wg.Wait()
	}

	if udpAddr := strings.TrimSpace(s.cfg.SyslogUDPAddr); udpAddr != "" {
		pc, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("listen syslog udp %q: %w", udpAddr, err)
		}
		closers = append(closers, func() { _ = pc.Close() })
		if s.cfg.OnSyslogListen != nil {
			s.cfg.OnSyslogListen("udp", pc.LocalAddr().String())
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveSyslogUDP(ctx, pc)
		}()
	}

	if tcpAddr := strings.TrimSpace(s.cfg.SyslogTCPAddr); tcpAddr != "" {
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("listen syslog tcp %q: %w", tcpAddr, err)
		}
		closers = append(closers, func() { _ = ln.Close() })
		if s.cfg.OnSyslogListen != nil {
			s.cfg.OnSyslogListen("tcp", ln.Addr().String())
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveSyslogTCP(ctx, ln)
		}()
	}

	go func() {
		<-ctx.Done()
		for _, fn := range closers {
			fn()
		}
	}()

	return cleanup, nil
}

func (s *Server) serveSyslogUDP(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, maxSyslogUDPPacketBytes)
	defaultYear := time.Now().UTC().Year()
	for {
		if ctx.Err() != nil {
			return
		}
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		payload := strings.TrimSpace(string(buf[:n]))
		if payload == "" {
			continue
		}
		s.syslogUDP.Add(1)
		evs, _, pErr := normalizer.ParseBytes([]byte(payload), normalizer.FormatAuto, "syslog-udp")
		if pErr != nil || len(evs) == 0 {
			_ = defaultYear
			continue
		}
		if remote != nil {
			for i := range evs {
				if evs[i].Metadata == nil {
					evs[i].Metadata = make(map[string]any)
				}
				evs[i].Metadata["syslog_remote"] = remote.String()
			}
		}
		s.IngestEvents(ctx, evs)
	}
}

func (s *Server) serveSyslogTCP(ctx context.Context, ln net.Listener) {
	sem := make(chan struct{}, maxSyslogTCPConns)
	var connWG sync.WaitGroup
	defer connWG.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		select {
		case sem <- struct{}{}:
			connWG.Add(1)
			go func(c net.Conn) {
				defer connWG.Done()
				defer func() {
					<-sem
					_ = c.Close()
				}()
				s.handleSyslogTCPConn(ctx, c)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) handleSyslogTCPConn(ctx context.Context, conn net.Conn) {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 8*1024), maxSyslogTCPLineBytes)
	defaultYear := time.Now().UTC().Year()
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(syslogTCPIdleTimeout))
		if !sc.Scan() {
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		s.syslogTCP.Add(1)
		evs, ok := normalizer.ParseLine(line, normalizer.FormatAuto, defaultYear)
		if !ok || len(evs) == 0 {
			continue
		}
		remoteStr := ""
		if conn.RemoteAddr() != nil {
			remoteStr = conn.RemoteAddr().String()
		}
		for i := range evs {
			if evs[i].Metadata == nil {
				evs[i].Metadata = make(map[string]any)
			}
			evs[i].Metadata["source_name"] = "syslog-tcp"
			if remoteStr != "" {
				evs[i].Metadata["syslog_remote"] = remoteStr
			}
		}
		s.IngestEvents(ctx, evs)
	}
}
