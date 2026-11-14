package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Sev string

const (
	SevCritical Sev = "critical"
	SevHigh     Sev = "high"
	SevMedium   Sev = "medium"
	SevLow      Sev = "low"
	SevInfo     Sev = "info"
)

var sevRank = map[Sev]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevInfo: 4}

// RawFinding is what a scan produces. Key is stable between scans so the workflow layer
// can tell "same problem as last time" from "new problem".
type RawFinding struct {
	Key      string
	CheckID  string
	Category string // network | tls | web | exposure | email | deep
	Severity Sev
	Evidence string // never contains secret values
	I18n     map[string]Text
}

type ScanOptions struct {
	Host     string
	Port     int // optional explicit port (treated as a web port as well)
	Sector   string
	Deep     bool
	Guard    *Guard
	Progress func(string)
}

type ScanResult struct {
	Findings  []RawFinding
	OpenPorts []int
	// Completed lists the categories that ran to the end. Only findings in completed
	// categories may be auto-resolved by a rescan, so a network blip never "fixes" anything.
	Completed map[string]bool
}

const userAgent = "CrimsonScanner/1.0 (authorized security assessment)"

func mkFinding(checkID, category string, sev Sev, subject, evidence string, i18n map[string]Text) RawFinding {
	return RawFinding{
		Key: checkID + "|" + subject, CheckID: checkID, Category: category,
		Severity: sev, Evidence: evidence, I18n: i18n,
	}
}

func RunScan(ctx context.Context, o ScanOptions) (*ScanResult, error) {
	say := o.Progress
	if say == nil {
		say = func(string) {}
	}
	res := &ScanResult{Completed: map[string]bool{}}
	var all []RawFinding

	if _, err := o.Guard.resolve(ctx, o.Host); err != nil {
		return nil, fmt.Errorf("cannot scan %s: %w", o.Host, err)
	}
	say("Target resolved")

	// 1. network exposure ------------------------------------------------------
	say("Checking exposed network services")
	open := scanPorts(ctx, o.Guard, o.Host, o.Port)
	res.OpenPorts = open
	res.Completed["network"] = true
	all = append(all, portFindings(open, o.Sector)...)
	say(fmt.Sprintf("Network: %d open port(s) found", len(open)))

	eps := pickWeb(open, o.Port)
	hasHTTPS := false
	for _, e := range eps {
		if e.Scheme == "https" {
			hasHTTPS = true
		}
	}

	// 2. TLS -------------------------------------------------------------------
	res.Completed["tls"] = true
	if hasHTTPS {
		say("Inspecting TLS certificate and protocol versions")
		for _, e := range eps {
			if e.Scheme != "https" {
				continue
			}
			f, err := checkTLS(ctx, o.Guard, o.Host, e.Port)
			if err != nil {
				say("TLS check incomplete: " + err.Error())
				res.Completed["tls"] = false
				continue
			}
			all = append(all, f...)
			break // one certificate per host is enough
		}
	}

	// 3. web + exposed files ---------------------------------------------------
	res.Completed["web"] = true
	res.Completed["exposure"] = true
	var webURLs []string
	if len(eps) > 0 {
		say("Checking website configuration")
		client := newHTTPClient(o.Guard)
		wf, base, err := checkWeb(ctx, client, o.Host, eps, hasHTTPS)
		if err != nil {
			say("Web check incomplete: " + err.Error())
			res.Completed["web"] = false
			res.Completed["exposure"] = false
		} else {
			all = append(all, wf...)
			webURLs = append(webURLs, base)
			say("Looking for exposed files and admin tools")
			ef := checkExposure(ctx, client, base)
			all = append(all, ef...)
			say(fmt.Sprintf("Exposure: %d exposed item(s)", len(ef)))
		}
	}

	// 4. e-mail spoofing protection -------------------------------------------
	res.Completed["email"] = false
	if apex := apexDomain(o.Host); apex != "" {
		say("Checking e-mail spoofing protection (SPF / DMARC)")
		ef, err := checkEmail(ctx, apex)
		if err != nil {
			say("E-mail check incomplete: " + err.Error())
		} else {
			all = append(all, ef...)
			res.Completed["email"] = true
		}
	}

	// 5. optional deep scan with nuclei ---------------------------------------
	if o.Deep {
		res.Completed["deep"] = false
		if len(webURLs) == 0 {
			say("Deep scan skipped: no web service found")
		} else {
			say("Running deep template scan (nuclei)")
			df, err := runNuclei(ctx, webURLs)
			if err != nil {
				say("Deep scan skipped: " + err.Error())
			} else {
				all = append(all, df...)
				res.Completed["deep"] = true
				say(fmt.Sprintf("Deep scan: %d finding(s)", len(df)))
			}
		}
	}

	// de-duplicate and order
	seen := map[string]bool{}
	for _, f := range all {
		if !seen[f.Key] {
			seen[f.Key] = true
			res.Findings = append(res.Findings, f)
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		return a.Key < b.Key
	})
	say(fmt.Sprintf("Scan finished: %d finding(s)", len(res.Findings)))
	return res, nil
}

// ---- ports -------------------------------------------------------------------

func scanPorts(ctx context.Context, g *Guard, host string, extra int) []int {
	set := map[int]bool{}
	for _, p := range riskyPorts {
		set[p.Port] = true
	}
	for _, p := range infoPorts {
		set[p] = true
	}
	if extra > 0 {
		set[extra] = true
	}
	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup
	sem := make(chan struct{}, 48)
	for p := range set {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			c, err := g.DialContext(cctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

func portFindings(open []int, sector string) []RawFinding {
	isOpen := map[int]bool{}
	for _, p := range open {
		isOpen[p] = true
	}
	var out []RawFinding
	for _, d := range riskyPorts {
		if !isOpen[d.Port] {
			continue
		}
		sev := d.Sev
		if d.Kind == "medical" && sector == "healthcare" {
			sev = SevCritical // patient data: treat as top priority for healthcare organisations
		}
		p := strconv.Itoa(d.Port)
		out = append(out, mkFinding("net.port."+p, "network", sev, p,
			"TCP port "+p+" accepted a connection from the internet",
			repPair(portTexts[d.Kind], "{name}", d.Name, "{port}", p)))
	}
	return out
}

type webEP struct {
	Scheme string
	Port   int
}

func (e webEP) base(host string) string {
	def := (e.Scheme == "https" && e.Port == 443) || (e.Scheme == "http" && e.Port == 80)
	if def {
		return e.Scheme + "://" + host
	}
	return e.Scheme + "://" + net.JoinHostPort(host, strconv.Itoa(e.Port))
}

func pickWeb(open []int, explicit int) []webEP {
	isOpen := map[int]bool{}
	for _, p := range open {
		isOpen[p] = true
	}
	var eps []webEP
	seen := map[webEP]bool{}
	add := func(s string, p int) {
		e := webEP{s, p}
		if isOpen[p] && !seen[e] {
			seen[e] = true
			eps = append(eps, e)
		}
	}
	if explicit > 0 {
		s := "http"
		if explicit == 443 || explicit == 8443 {
			s = "https"
		}
		add(s, explicit)
	}
	add("https", 443)
	add("http", 80)
	add("https", 8443)
	add("http", 8080)
	return eps
}

// ---- TLS ---------------------------------------------------------------------

func tlsHandshake(ctx context.Context, g *Guard, host string, port int, cfg *tls.Config) (tls.ConnectionState, error) {
	conn, err := g.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tc.ConnectionState(), nil
}

func checkTLS(ctx context.Context, g *Guard, host string, port int) ([]RawFinding, error) {
	subject := net.JoinHostPort(host, strconv.Itoa(port))
	// Certificate validation is done by hand below so each problem can be reported
	// precisely instead of as one generic handshake error.
	state, err := tlsHandshake(ctx, g, host, port, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("server sent no certificate")
	}
	leaf := state.PeerCertificates[0]
	var out []RawFinding
	now := time.Now()

	if now.After(leaf.NotAfter) {
		out = append(out, mkFinding("tls.expired", "tls", SevHigh, subject,
			"Certificate expired on "+leaf.NotAfter.Format("2006-01-02"), txtTLSExpired))
	} else if days := int(leaf.NotAfter.Sub(now).Hours() / 24); days <= 30 {
		sev := SevLow
		if days <= 14 {
			sev = SevMedium
		}
		out = append(out, mkFinding("tls.expiring", "tls", sev, subject,
			"Certificate expires on "+leaf.NotAfter.Format("2006-01-02"),
			repPair(txtTLSExpiring, "{n}", strconv.Itoa(days))))
	}

	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	mid := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2) // judge trust separately from expiry
	if _, verr := leaf.Verify(x509.VerifyOptions{Intermediates: inter, CurrentTime: mid}); verr != nil {
		msg := verr.Error()
		if len(msg) > 160 {
			msg = msg[:160]
		}
		out = append(out, mkFinding("tls.untrusted", "tls", SevHigh, subject, msg, txtTLSUntrusted))
	}
	if herr := leaf.VerifyHostname(host); herr != nil {
		names := leaf.DNSNames
		if len(names) > 5 {
			names = names[:5]
		}
		out = append(out, mkFinding("tls.hostname", "tls", SevMedium, subject,
			"Certificate is valid for: "+strings.Join(names, ", "), txtTLSHostname))
	}

	if _, lerr := tlsHandshake(ctx, g, host, port, &tls.Config{
		ServerName: host, InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11,
	}); lerr == nil {
		out = append(out, mkFinding("tls.legacy", "tls", SevMedium, subject,
			"Server completed a handshake using TLS 1.0 or 1.1", txtTLSLegacy))
	}
	return out, nil
}

// ---- web ---------------------------------------------------------------------

func newHTTPClient(g *Guard) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           g.DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // certificate is judged in checkTLS
		TLSHandshakeTimeout:   6 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func httpGet(ctx context.Context, c *http.Client, u string, max int64) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	return resp, body, nil
}

// fetchFollow follows redirects by hand, and only to the same site (host or www.host).
func fetchFollow(ctx context.Context, c *http.Client, start, host string) (*http.Response, []byte, *url.URL, error) {
	cur := start
	for hop := 0; hop < 4; hop++ {
		resp, body, err := httpGet(ctx, c, cur, 64<<10)
		if err != nil {
			return nil, nil, nil, err
		}
		u, _ := url.Parse(cur)
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" {
			return resp, body, u, nil
		}
		next, err := u.Parse(loc)
		if err != nil {
			return resp, body, u, nil
		}
		h := next.Hostname()
		if h != host && h != "www."+host && "www."+h != host {
			return resp, body, u, nil
		}
		cur = next.String()
	}
	return nil, nil, nil, errors.New("too many redirects")
}

func checkWeb(ctx context.Context, c *http.Client, host string, eps []webEP, hasHTTPS bool) ([]RawFinding, string, error) {
	primary := eps[0]
	resp, _, final, err := fetchFollow(ctx, c, primary.base(host)+"/", host)
	if err != nil {
		return nil, "", err
	}
	var out []RawFinding
	finalHTTPS := final.Scheme == "https"

	if !hasHTTPS {
		out = append(out, mkFinding("web.no_https", "web", SevHigh, host,
			"Only plain HTTP is served ("+primary.base(host)+")", txtNoHTTPS))
	} else {
		for _, e := range eps {
			if e.Scheme != "http" {
				continue
			}
			r, _, err := httpGet(ctx, c, e.base(host)+"/", 4<<10)
			if err != nil {
				break
			}
			if loc := r.Header.Get("Location"); r.StatusCode < 300 || r.StatusCode > 399 || !strings.HasPrefix(strings.ToLower(loc), "https://") {
				out = append(out, mkFinding("web.no_redirect", "web", SevLow, host,
					fmt.Sprintf("%s answered HTTP %d without redirecting to HTTPS", e.base(host), r.StatusCode), txtNoRedirect))
			}
			break
		}
	}

	h := resp.Header
	csp := h.Get("Content-Security-Policy")
	if finalHTTPS && h.Get("Strict-Transport-Security") == "" {
		out = append(out, mkFinding("web.hsts", "web", SevLow, host, "No Strict-Transport-Security header", txtHSTS))
	}
	if csp == "" {
		out = append(out, mkFinding("web.csp", "web", SevMedium, host, "No Content-Security-Policy header", txtCSP))
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		out = append(out, mkFinding("web.xfo", "web", SevLow, host, "No X-Frame-Options or frame-ancestors", txtXFO))
	}
	if !strings.EqualFold(h.Get("X-Content-Type-Options"), "nosniff") {
		out = append(out, mkFinding("web.nosniff", "web", SevLow, host, "No X-Content-Type-Options: nosniff", txtNosniff))
	}
	verRe := regexp.MustCompile(`\d+\.\d+`)
	for _, name := range []string{"Server", "X-Powered-By"} {
		if v := h.Get(name); v != "" && verRe.MatchString(v) {
			out = append(out, mkFinding("web.server_version", "web", SevLow, name,
				name+": "+v, txtServerVer))
		}
	}
	n := 0
	for _, ck := range resp.Cookies() {
		if n >= 5 {
			break
		}
		var missing []string
		if finalHTTPS && !ck.Secure {
			missing = append(missing, "Secure")
		}
		if !ck.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if len(missing) > 0 {
			n++
			out = append(out, mkFinding("web.cookie", "web", SevLow, ck.Name,
				"Missing: "+strings.Join(missing, ", "), repPair(txtCookie, "{name}", ck.Name)))
		}
	}
	base := final.Scheme + "://" + final.Host
	return out, base, nil
}

// ---- exposed files -----------------------------------------------------------

type probe struct {
	Path  string
	Kind  string
	Sev   Sev
	Match func(status int, body []byte) (bool, string)
}

var envLine = regexp.MustCompile(`(?m)^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+`)

func isHTML(b []byte) bool {
	head := strings.ToLower(string(b[:min(len(b), 512)]))
	return strings.Contains(head, "<html") || strings.Contains(head, "<!doctype")
}

func contains(sub ...string) func(int, []byte) (bool, string) {
	return func(st int, b []byte) (bool, string) {
		if st != 200 {
			return false, ""
		}
		s := string(b)
		for _, x := range sub {
			if strings.Contains(s, x) {
				return true, fmt.Sprintf("HTTP 200, %d bytes returned, content matches expected signature", len(b))
			}
		}
		return false, ""
	}
}

func prefix(p string) func(int, []byte) (bool, string) {
	return func(st int, b []byte) (bool, string) {
		if st == 200 && bytes.HasPrefix(b, []byte(p)) {
			return true, fmt.Sprintf("HTTP 200, file header matches expected signature (%d bytes read)", len(b))
		}
		return false, ""
	}
}

func envMatch(st int, b []byte) (bool, string) {
	if st != 200 || isHTML(b) {
		return false, ""
	}
	if n := len(envLine.FindAll(b, -1)); n >= 2 {
		return true, fmt.Sprintf("HTTP 200, %d configuration lines readable (values are never stored by Crimson)", n)
	}
	return false, ""
}

var probes = []probe{
	{"/.env", "secrets", SevCritical, envMatch},
	{"/.env.production", "secrets", SevCritical, envMatch},
	{"/.env.local", "secrets", SevCritical, envMatch},
	{"/wp-config.php.bak", "secrets", SevCritical, contains("DB_PASSWORD")},
	{"/wp-config.php~", "secrets", SevCritical, contains("DB_PASSWORD")},
	{"/.htpasswd", "secrets", SevHigh, func(st int, b []byte) (bool, string) {
		ok := st == 200 && regexp.MustCompile(`(?m)^[^:\s]+:(\$apr1\$|\{SHA\}|\$2[aby]\$)`).Match(b)
		return ok, "HTTP 200, password hash file readable"
	}},
	{"/.git/HEAD", "vcs", SevHigh, func(st int, b []byte) (bool, string) {
		return st == 200 && strings.HasPrefix(strings.TrimSpace(string(b)), "ref:"), "HTTP 200, repository metadata readable"
	}},
	{"/.git/config", "vcs", SevHigh, contains("[core]")},
	{"/backup.zip", "backup", SevCritical, prefix("PK\x03\x04")},
	{"/site.zip", "backup", SevCritical, prefix("PK\x03\x04")},
	{"/www.zip", "backup", SevCritical, prefix("PK\x03\x04")},
	{"/backup.tar.gz", "backup", SevCritical, prefix("\x1f\x8b")},
	{"/backup.sql", "backup", SevCritical, contains("CREATE TABLE", "INSERT INTO", "mysqldump")},
	{"/db.sql", "backup", SevCritical, contains("CREATE TABLE", "INSERT INTO", "mysqldump")},
	{"/dump.sql", "backup", SevCritical, contains("CREATE TABLE", "INSERT INTO", "mysqldump")},
	{"/database.sql", "backup", SevCritical, contains("CREATE TABLE", "INSERT INTO", "mysqldump")},
	{"/phpinfo.php", "info", SevMedium, contains("phpinfo()", "PHP Version")},
	{"/server-status", "info", SevMedium, contains("Apache Server Status")},
	{"/actuator/env", "info", SevHigh, contains("propertySources")},
	{"/phpmyadmin/", "admin", SevMedium, contains("phpMyAdmin")},
	{"/adminer.php", "admin", SevMedium, contains("Adminer")},
	{"/swagger.json", "docs", SevLow, contains(`"swagger"`, `"openapi"`)},
	{"/openapi.json", "docs", SevLow, contains(`"swagger"`, `"openapi"`)},
	{"/.DS_Store", "misc", SevLow, prefix("\x00\x00\x00\x01Bud1")},
}

func checkExposure(ctx context.Context, c *http.Client, base string) []RawFinding {
	var mu sync.Mutex
	var out []RawFinding
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, p := range probes {
		wg.Add(1)
		sem <- struct{}{}
		go func(p probe) {
			defer wg.Done()
			defer func() { <-sem }()
			resp, body, err := httpGet(ctx, c, base+p.Path, 64<<10)
			if err != nil {
				return
			}
			if ok, ev := p.Match(resp.StatusCode, body); ok {
				f := mkFinding("exposure."+p.Path, "exposure", p.Sev, p.Path, ev,
					repPair(exposureTexts[p.Kind], "{path}", p.Path))
				mu.Lock()
				out = append(out, f)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return out
}

// ---- e-mail DNS --------------------------------------------------------------

var secondLevel = map[string]bool{"co": true, "com": true, "org": true, "net": true, "gov": true, "edu": true, "ac": true}

// apexDomain returns the host if it looks like a registrable domain (SPF/DMARC live there),
// or "" for IPs and subdomains. A tiny heuristic on purpose: no public-suffix list needed.
func apexDomain(host string) string {
	if net.ParseIP(host) != nil || host == "localhost" {
		return ""
	}
	host = strings.TrimPrefix(host, "www.")
	labels := strings.Split(host, ".")
	switch {
	case len(labels) == 2:
		return host
	case len(labels) == 3 && secondLevel[labels[1]] && len(labels[2]) == 2:
		return host
	}
	return ""
}

func lookupTXT(ctx context.Context, name string) ([]string, error) {
	txt, err := net.DefaultResolver.LookupTXT(ctx, name)
	var de *net.DNSError
	if err != nil && errors.As(err, &de) && de.IsNotFound {
		return nil, nil
	}
	return txt, err
}

func checkEmail(ctx context.Context, apex string) ([]RawFinding, error) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var out []RawFinding

	txt, err := lookupTXT(cctx, apex)
	if err != nil {
		return nil, err
	}
	spf := ""
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = strings.ToLower(t)
		}
	}
	switch {
	case spf == "":
		out = append(out, mkFinding("email.spf_missing", "email", SevMedium, apex, "No v=spf1 TXT record at "+apex, txtSPFMissing))
	case strings.Contains(spf, "+all") || strings.Contains(spf, "?all"):
		out = append(out, mkFinding("email.spf_weak", "email", SevLow, apex, "SPF ends with a permissive mechanism: "+spf, txtSPFWeak))
	}

	dm, err := lookupTXT(cctx, "_dmarc."+apex)
	if err != nil {
		return nil, err
	}
	dmarc := ""
	for _, t := range dm {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			dmarc = strings.ToLower(t)
		}
	}
	switch {
	case dmarc == "":
		out = append(out, mkFinding("email.dmarc_missing", "email", SevMedium, apex, "No DMARC TXT record at _dmarc."+apex, txtDMARCMissing))
	case strings.Contains(strings.ReplaceAll(dmarc, " ", ""), "p=none"):
		out = append(out, mkFinding("email.dmarc_none", "email", SevLow, apex, "DMARC policy: "+dmarc, txtDMARCNone))
	}
	return out, nil
}

// ---- optional deep scan ------------------------------------------------------

func runNuclei(ctx context.Context, urls []string) ([]RawFinding, error) {
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		return nil, errors.New("nuclei is not installed on this server")
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	args := []string{"-silent", "-jsonl", "-severity", "medium,high,critical",
		"-etags", "dos,fuzz,bruteforce,intrusive", "-rl", "30", "-timeout", "8"}
	for _, u := range urls {
		args = append(args, "-u", u)
	}
	out, runErr := exec.CommandContext(cctx, bin, args...).Output()
	if runErr != nil && len(out) == 0 {
		return nil, fmt.Errorf("nuclei failed: %v", runErr)
	}
	var res []RawFinding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var n struct {
			ID   string `json:"template-id"`
			Info struct {
				Name        string `json:"name"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
			} `json:"info"`
			MatchedAt string `json:"matched-at"`
		}
		if json.Unmarshal([]byte(line), &n) != nil || n.ID == "" {
			continue
		}
		sev := Sev(strings.ToLower(n.Info.Severity))
		if _, ok := sevRank[sev]; !ok {
			sev = SevMedium
		}
		desc := n.Info.Description
		if desc == "" {
			desc = "A known vulnerability signature matched this service."
		}
		fix := "Update the affected software or apply the vendor's mitigation. The Crimson team will advise on the exact steps."
		fixAZ := "Təsirə məruz qalan proqramı yeniləyin və ya istehsalçının təklif etdiyi həlli tətbiq edin. Crimson komandası dəqiq addımlar barədə məsləhət verəcək."
		res = append(res, mkFinding("deep."+n.ID, "deep", sev, n.MatchedAt, "Matched at "+n.MatchedAt,
			pair(tx(n.Info.Name, desc, fix), tx(n.Info.Name, desc, fixAZ))))
	}
	return res, nil
}
