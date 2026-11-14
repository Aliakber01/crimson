package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Guard is the single choke point for every outbound connection the scanner makes.
// It resolves the name itself and refuses private / loopback / link-local addresses
// (unless AllowPrivate is set for local demos), so a customer can never use Crimson
// to probe the network it runs in (SSRF) - not even through redirects or DNS rebinding,
// because the check happens on every dial.
type Guard struct {
	AllowPrivate bool
	Timeout      time.Duration
}

var cgnat = func() *net.IPNet { _, n, _ := net.ParseCIDR("100.64.0.0/10"); return n }()

func disallowedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		(ip.To4() != nil && cgnat.Contains(ip))
}

func (g *Guard) resolve(ctx context.Context, host string) ([]net.IP, error) {
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("host does not resolve (%v)", err)
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	var allowed []net.IP
	for _, ip := range ips {
		if g.AllowPrivate || !disallowedIP(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("host resolves only to private or internal addresses, which are not allowed")
	}
	return allowed, nil
}

func (g *Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := g.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	timeout := g.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	var last error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// parseTarget accepts "example.com", "https://example.com/path", "10.0.0.5:8080".
func parseTarget(s string) (host string, port int, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	switch strings.Count(s, ":") {
	case 0:
		host = s
	case 1:
		var p string
		host, p, _ = strings.Cut(s, ":")
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("invalid port")
		}
	default:
		return "", 0, errors.New("IPv6 targets are not supported yet")
	}
	if host == "" || len(host) > 253 {
		return "", 0, errors.New("invalid host")
	}
	if net.ParseIP(host) == nil && !hostRe.MatchString(host) {
		return "", 0, errors.New("invalid host name")
	}
	return host, port, nil
}

func canonicalTarget(host string, port int) string {
	if port > 0 {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return host
}

// isLocalLiteral is true for IP literals in private ranges and "localhost" (no DNS involved).
func isLocalLiteral(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && disallowedIP(ip)
}
