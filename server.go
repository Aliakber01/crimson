package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

type Config struct {
	Addr           string
	DataPath       string
	AllowPrivate   bool
	Demo           bool
	Sandbox        bool // public hosting: demo accounts only, no real-system shortcuts
	SandboxSignup  bool
	BaseURL        string
	TrustProxy     bool
	Mail           *Mailer
	SandboxHint    []map[string]string
	AnthropicKey   string
	AnthropicModel string
}

type Server struct {
	cfg    Config
	store  *Store
	guard  *Guard
	mux    *http.ServeMux
	authRL *rateLimiter
	mailRL *rateLimiter
}

type apiErr struct {
	Code int
	Msg  string
}

func (e apiErr) Error() string { return e.Msg }

func fail(code int, msg string) error { return apiErr{code, msg} }

type Ctx struct {
	R     *http.Request
	W     http.ResponseWriter
	DB    *DB
	U     *User
	Body  []byte
	S     *Server
	After []func()
}

func (c *Ctx) Bind(v any) error {
	if len(c.Body) == 0 {
		return nil
	}
	if err := json.Unmarshal(c.Body, v); err != nil {
		return fail(400, "invalid JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func replyError(w http.ResponseWriter, err error) {
	var ae apiErr
	if errors.As(err, &ae) {
		writeErr(w, ae.Code, ae.Msg)
		return
	}
	log.Printf("internal error: %v", err)
	writeErr(w, 500, "internal error")
}

// requestAllowed blocks cross-site state changes: JSON content type (cannot be sent by a
// plain HTML form) plus an Origin check, on top of SameSite=Lax session cookies.
func requestAllowed(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeErr(w, 415, "JSON content type required")
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		if u, err := url.Parse(o); err != nil || u.Host != r.Host {
			writeErr(w, 403, "cross-origin request blocked")
			return false
		}
	}
	return true
}

// handle registers an API route that runs inside the database lock.
// role: "" = public (user optional), "user" = any signed-in user, "staff" = Crimson team only.
func (s *Server) handle(pattern, role string, mutate bool, fn func(*Ctx) (any, error)) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !requestAllowed(w, r) {
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeErr(w, 413, "request too large")
			return
		}
		var out any
		var after []func()
		run := func(db *DB) error {
			c := &Ctx{R: r, W: w, DB: db, Body: body, S: s, U: userFromRequest(db, r)}
			switch {
			case role != "" && c.U == nil:
				return fail(401, "sign in required")
			case role == "staff" && c.U.Role != "staff":
				return fail(403, "staff only")
			}
			res, err := fn(c)
			out, after = res, c.After
			return err
		}
		if mutate {
			err = s.store.Update(run)
		} else {
			err = s.store.View(run)
		}
		if err != nil {
			replyError(w, err)
			return
		}
		if out == nil {
			out = map[string]bool{"ok": true}
		}
		writeJSON(w, 200, out)
		for _, f := range after {
			f()
		}
	})
}

// handleRaw is for routes that must talk to the network (verification, AI), and therefore
// must not hold the database lock while they wait.
func (s *Server) handleRaw(pattern, role string, fn func(w http.ResponseWriter, r *http.Request, u User)) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !requestAllowed(w, r) {
			return
		}
		var u *User
		_ = s.store.View(func(db *DB) error {
			if x := userFromRequest(db, r); x != nil {
				cp := *x
				u = &cp
			}
			return nil
		})
		if u == nil || (role == "staff" && u.Role != "staff") {
			writeErr(w, map[bool]int{true: 401, false: 403}[u == nil], "not allowed")
			return
		}
		fn(w, r, *u)
	})
}

func (c *Ctx) staff() bool { return c.U != nil && c.U.Role == "staff" }

func (c *Ctx) target(id string) (*Target, error) {
	t := c.DB.Targets[id]
	if t == nil || (!c.staff() && t.OrgID != c.U.OrgID) {
		return nil, fail(404, "not found")
	}
	return t, nil
}

func (c *Ctx) finding(id string) (*Finding, *Target, error) {
	f := c.DB.Findings[id]
	if f == nil {
		return nil, nil, fail(404, "not found")
	}
	t, err := c.target(f.TargetID)
	if err != nil {
		return nil, nil, err
	}
	return f, t, nil
}

func (c *Ctx) author() string {
	if c.U.Name != "" {
		return c.U.Name
	}
	return c.U.Email
}

// ---- view models -------------------------------------------------------------

type targetSummary struct {
	ID         string      `json:"id"`
	Host       string      `json:"host"`
	OrgID      string      `json:"orgId"`
	Org        string      `json:"org"`
	Sector     string      `json:"sector"`
	Verified   bool        `json:"verified"`
	Scanning   bool        `json:"scanning"`
	Score      int         `json:"score"`
	Grade      string      `json:"grade"`
	Counts     map[Sev]int `json:"counts"`
	Requested  int         `json:"requested"`
	InProgress int         `json:"inProgress"`
	Fixed      int         `json:"fixed"`
	Scanned    bool        `json:"scanned"`
	LastScan   *time.Time  `json:"lastScan,omitempty"`
	CheckDone  int         `json:"checkDone"`
	CheckTotal int         `json:"checkTotal"`
}

func (db *DB) summarize(t *Target) targetSummary {
	fs := db.targetFindings(t.ID)
	score, grade, counts := scoreOf(fs)
	org := db.Orgs[t.OrgID]
	s := targetSummary{ID: t.ID, Host: t.Host, OrgID: t.OrgID, Verified: t.Verified, Scanning: t.Scanning,
		Score: score, Grade: grade, Counts: counts, CheckTotal: len(t.Checklist)}
	if org != nil {
		s.Org, s.Sector = org.Name, org.Sector
	}
	for _, f := range fs {
		switch f.Status {
		case "requested":
			s.Requested++
		case "in_progress":
			s.InProgress++
		case "fixed":
			s.Fixed++
		}
	}
	for _, ci := range t.Checklist {
		if ci.Done {
			s.CheckDone++
		}
	}
	if sc := db.Scans[t.LastScanID]; sc != nil && sc.Status == "done" {
		s.Scanned = true
		s.LastScan = &sc.Finished
	} else {
		for _, sc := range db.Scans {
			if sc.TargetID == t.ID && sc.Status == "done" && (s.LastScan == nil || sc.Finished.After(*s.LastScan)) {
				s.Scanned, s.LastScan = true, &sc.Finished
			}
		}
	}
	return s
}

func sortFindings(fs []*Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if isActive(a) != isActive(b) {
			return isActive(a)
		}
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		return a.FirstSeen.Before(b.FirstSeen)
	})
}

// ---- construction ------------------------------------------------------------

var validSectors = map[string]bool{"general": true, "healthcare": true, "education": true, "government": true, "retail": true, "finance": true, "ngo": true}
var validStatus = map[string]bool{"open": true, "requested": true, "in_progress": true, "fixed": true, "verified": true, "accepted": true}

func NewServer(cfg Config, store *Store) *Server {
	s := &Server{
		cfg: cfg, store: store, mux: http.NewServeMux(),
		guard:  &Guard{AllowPrivate: cfg.AllowPrivate, Timeout: 2 * time.Second},
		authRL: newRateLimiter(20, 10*time.Minute),
		mailRL: newRateLimiter(3, time.Hour),
	}
	trustProxy = cfg.TrustProxy
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return secure(s.mux) }

// baseURL is used in e-mail links. It comes from configuration, never from the request Host header
// (which an attacker can set to poison reset links).
func (s *Server) baseURL() string {
	if u := strings.TrimRight(s.cfg.BaseURL, "/"); u != "" {
		return u
	}
	a := s.cfg.Addr
	if strings.HasPrefix(a, ":") {
		a = "127.0.0.1" + a
	}
	return "http://" + a
}

// sandboxDemoHost is the only local address a public sandbox is allowed to scan.
const sandboxDemoHost = "127.0.0.1:8081"

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/report/") {
			h.Set("Cache-Control", "no-store")
		}
		if !strings.HasPrefix(r.URL.Path, "/report/") {
			h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	sub, _ := fs.Sub(webFS, "web")
	s.mux.Handle("GET /", http.FileServer(http.FS(sub)))

	// ---- auth ----
	s.handle("POST /api/auth/register", "", true, func(c *Ctx) (any, error) {
		if c.S.cfg.Sandbox && !c.S.cfg.SandboxSignup {
			return nil, fail(403, "sign-up is closed in the public sandbox; use the demo accounts")
		}
		if !c.S.authRL.allow(clientIP(c.R)) {
			return nil, fail(429, "too many attempts, try again later")
		}
		var in struct{ Email, Password, Name, Org, Sector string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		email := strings.ToLower(strings.TrimSpace(in.Email))
		switch {
		case !strings.Contains(email, "@") || len(email) > 200:
			return nil, fail(400, "enter a valid e-mail address")
		case len(in.Password) < 10:
			return nil, fail(400, "password must be at least 10 characters")
		case strings.TrimSpace(in.Org) == "" || len(in.Org) > 120:
			return nil, fail(400, "organisation name is required")
		case !validSectors[in.Sector]:
			in.Sector = "general"
		}
		for _, u := range c.DB.Users {
			if u.Email == email {
				return nil, fail(409, "an account with this e-mail already exists")
			}
		}
		org := &Org{ID: newID("o"), Name: strings.TrimSpace(in.Org), Sector: in.Sector, Created: time.Now()}
		u := newUser(email, in.Name, "customer", org.ID, in.Password)
		c.DB.Orgs[org.ID], c.DB.Users[u.ID] = org, u
		c.DB.startSession(c.W, c.R, u.ID)
		c.DB.audit(email, "register", org.Name)
		return meView(c.DB, u), nil
	})

	s.handle("POST /api/auth/login", "", true, func(c *Ctx) (any, error) {
		if !c.S.authRL.allow(clientIP(c.R)) {
			return nil, fail(429, "too many attempts, try again later")
		}
		var in struct{ Email, Password string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		email := strings.ToLower(strings.TrimSpace(in.Email))
		var found *User
		for _, u := range c.DB.Users {
			if u.Email == email {
				found = u
			}
		}
		if !checkPassword(found, in.Password) {
			return nil, apiErr{401, "wrong e-mail or password"}
		}
		c.DB.startSession(c.W, c.R, found.ID)
		c.DB.audit(email, "login", found.Role)
		return meView(c.DB, found), nil
	})

	s.handle("POST /api/auth/logout", "", true, func(c *Ctx) (any, error) {
		clearSession(c.W, c.R, c.DB)
		return nil, nil
	})

	s.handle("POST /api/auth/forgot", "", true, func(c *Ctx) (any, error) {
		if !c.S.authRL.allow(clientIP(c.R)) {
			return nil, fail(429, "too many attempts, try again later")
		}
		var in struct{ Email, Lang string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		email := strings.ToLower(strings.TrimSpace(in.Email))
		if !strings.Contains(email, "@") || len(email) > 200 || strings.ContainsAny(email, "\r\n<>\", ;") {
			return nil, fail(400, "enter a valid e-mail address")
		}
		lang := "en"
		if in.Lang == "az" {
			lang = "az"
		}
		var found *User
		for _, u := range c.DB.Users {
			if u.Email == email {
				found = u
			}
		}
		// The answer is identical whether or not the account exists (no account enumeration).
		if found != nil && c.S.mailRL.allow(email) {
			now := time.Now()
			for k, r := range c.DB.Resets {
				if r.UserID == found.ID || now.After(r.Expires) {
					delete(c.DB.Resets, k)
				}
			}
			token := randomHex(32)
			c.DB.Resets[sessionKey(token)] = &Reset{UserID: found.ID, Expires: now.Add(time.Hour)}
			c.DB.audit(email, "password.reset.requested", "")
			link, mailer := c.S.baseURL()+"/#/reset/"+token, c.S.cfg.Mail
			c.After = append(c.After, func() { go sendResetMail(mailer, email, link, lang) })
		}
		return map[string]bool{"ok": true}, nil
	})

	s.handle("POST /api/auth/reset", "", true, func(c *Ctx) (any, error) {
		if !c.S.authRL.allow(clientIP(c.R)) {
			return nil, fail(429, "too many attempts, try again later")
		}
		var in struct{ Token, Password string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		if len(in.Password) < 10 {
			return nil, fail(400, "password must be at least 10 characters")
		}
		key := sessionKey(in.Token)
		r := c.DB.Resets[key]
		if r == nil || time.Now().After(r.Expires) || c.DB.Users[r.UserID] == nil {
			delete(c.DB.Resets, key)
			return nil, fail(400, "this reset link is invalid or has expired")
		}
		u := c.DB.Users[r.UserID]
		salt := make([]byte, 16)
		_, _ = rand.Read(salt)
		u.Salt, u.Hash = salt, hashPassword(in.Password, salt)
		delete(c.DB.Resets, key)
		for k, s := range c.DB.Sessions { // sign out everywhere
			if s.UserID == u.ID {
				delete(c.DB.Sessions, k)
			}
		}
		c.DB.audit(u.Email, "password.reset.done", "")
		return nil, nil
	})

	s.handle("GET /api/me", "", false, func(c *Ctx) (any, error) {
		if c.U == nil {
			return map[string]any{"user": nil}, nil
		}
		return meView(c.DB, c.U), nil
	})

	s.handle("GET /api/meta", "", false, func(c *Ctx) (any, error) {
		_, nucleiErr := exec.LookPath("nuclei")
		return map[string]any{
			"checklist":    checklistCatalog,
			"sectors":      []string{"general", "healthcare", "education", "government", "retail", "finance", "ngo"},
			"ai":           c.S.cfg.AnthropicKey != "",
			"deep":         nucleiErr == nil,
			"allowPrivate": c.S.cfg.AllowPrivate,
			"demo":         c.S.cfg.Demo,
			"sandbox":      c.S.cfg.Sandbox,
			"accounts":     c.S.cfg.SandboxHint,
			"signup":       !c.S.cfg.Sandbox || c.S.cfg.SandboxSignup,
		}, nil
	})

	// Demo only: lets staff flip the bundled weak demo site into its fixed / broken state from the dashboard.
	s.handle("POST /api/demo/{action}", "staff", true, func(c *Ctx) (any, error) {
		a := c.R.PathValue("action")
		if !c.S.cfg.Demo || (a != "fix" && a != "break") {
			return nil, errors.New("not available")
		}
		cl := &http.Client{Timeout: 5 * time.Second}
		resp, err := cl.Get("http://127.0.0.1:8081/_demo/" + a)
		if err != nil {
			return nil, errors.New("demo site is not running (start it with: crimson demo)")
		}
		resp.Body.Close()
		return map[string]any{"ok": true}, nil
	})

	// ---- targets ----
	s.handle("GET /api/targets", "user", false, func(c *Ctx) (any, error) {
		out := []targetSummary{}
		for _, t := range c.DB.Targets {
			if c.staff() || t.OrgID == c.U.OrgID {
				out = append(out, c.DB.summarize(t))
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
		return out, nil
	})

	s.handle("POST /api/targets", "user", true, func(c *Ctx) (any, error) {
		if c.staff() {
			return nil, fail(403, "targets are added by customers")
		}
		var in struct{ Host string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		host, port, err := parseTarget(in.Host)
		if err != nil {
			return nil, fail(400, err.Error())
		}
		canon := canonicalTarget(host, port)
		if isLocalLiteral(host) && !c.S.cfg.AllowPrivate && !(c.S.cfg.Sandbox && canon == sandboxDemoHost) {
			return nil, fail(400, "private and local addresses cannot be scanned")
		}
		count := 0
		for _, t := range c.DB.Targets {
			if t.OrgID == c.U.OrgID {
				count++
				if t.Host == canon {
					return nil, fail(409, "this target is already added")
				}
			}
		}
		if count >= 20 {
			return nil, fail(400, "target limit reached")
		}
		org := c.DB.Orgs[c.U.OrgID]
		t := &Target{ID: newID("t"), OrgID: org.ID, Host: canon, Token: randomHex(10), Created: time.Now(), Checklist: seedChecklist(org.Sector)}
		if isLocalLiteral(host) { // local demo mode: no DNS/file proof possible or needed
			t.Verified, t.VerifiedBy, t.VerifiedAt = true, "local-dev-mode", time.Now()
		}
		c.DB.Targets[t.ID] = t
		c.DB.audit(c.U.Email, "target.add", canon)
		return c.DB.summarize(t), nil
	})

	s.handle("GET /api/targets/{id}", "user", false, func(c *Ctx) (any, error) {
		t, err := c.target(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		fs := c.DB.targetFindings(t.ID)
		sortFindings(fs)
		scans := []*Scan{}
		if fs == nil {
			fs = []*Finding{}
		}
		for _, sc := range c.DB.Scans {
			if sc.TargetID == t.ID {
				cp := *sc
				scans = append(scans, &cp)
			}
		}
		sort.Slice(scans, func(i, j int) bool { return scans[i].Started.After(scans[j].Started) })
		if len(scans) > 8 {
			scans = scans[:8]
		}
		for i := 1; i < len(scans); i++ {
			scans[i].Log = nil
		}
		return map[string]any{
			"summary": c.DB.summarize(t), "target": t, "org": c.DB.Orgs[t.OrgID],
			"findings": fs, "scans": scans,
		}, nil
	})

	s.handle("POST /api/targets/{id}/scan", "user", true, func(c *Ctx) (any, error) {
		t, err := c.target(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		var in struct{ Deep bool }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		if !t.Verified {
			return nil, fail(403, "prove ownership of this target before scanning it")
		}
		if t.Scanning {
			return nil, fail(409, "a scan is already running")
		}
		if prev := c.DB.Scans[t.LastScanID]; prev != nil && !c.staff() && time.Since(prev.Started) < 60*time.Second {
			return nil, fail(429, "please wait a minute between scans")
		}
		host, port, err := parseTarget(t.Host)
		if err != nil {
			return nil, fail(400, err.Error())
		}
		sector := c.DB.Orgs[t.OrgID].Sector
		sc := &Scan{ID: newID("s"), TargetID: t.ID, Started: time.Now(), Status: "running", Deep: in.Deep, By: c.U.Email, Counts: map[Sev]int{}}
		c.DB.Scans[sc.ID] = sc
		t.Scanning, t.LastScanID = true, sc.ID
		c.DB.audit(c.U.Email, "scan.start", t.Host)
		scanID, targetID := sc.ID, t.ID
		c.After = append(c.After, func() {
			go c.S.runScan(scanID, targetID, ScanOptions{Host: host, Port: port, Sector: sector, Deep: in.Deep})
		})
		return map[string]string{"scanId": scanID}, nil
	})

	s.handle("GET /api/scans/{id}", "user", false, func(c *Ctx) (any, error) {
		sc := c.DB.Scans[c.R.PathValue("id")]
		if sc == nil {
			return nil, fail(404, "not found")
		}
		if _, err := c.target(sc.TargetID); err != nil {
			return nil, err
		}
		return sc, nil
	})

	s.handleRaw("POST /api/targets/{id}/verify", "user", s.verifyHandler)

	s.handle("POST /api/targets/{id}/force-verify", "staff", true, func(c *Ctx) (any, error) {
		if c.S.cfg.Sandbox {
			return nil, fail(403, "manual ownership confirmation is disabled in the public sandbox")
		}
		t, err := c.target(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		var in struct{ Note string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		if strings.TrimSpace(in.Note) == "" {
			return nil, fail(400, "write how ownership was confirmed (e.g. signed authorisation letter)")
		}
		t.Verified, t.VerifiedAt = true, time.Now()
		t.VerifiedBy = "staff " + c.U.Email + ": " + in.Note
		c.DB.audit(c.U.Email, "target.force-verify", t.Host+" — "+in.Note)
		return nil, nil
	})

	s.handle("POST /api/targets/{id}/request-all", "user", true, func(c *Ctx) (any, error) {
		t, err := c.target(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		n := 0
		now := time.Now()
		for _, f := range c.DB.targetFindings(t.ID) {
			if f.Status == "open" && isActive(f) {
				f.Status, f.Updated = "requested", now
				f.Comments = append(f.Comments, Comment{now, c.author(), c.U.Role, "Requested a fix for this problem."})
				n++
			}
		}
		if n > 0 {
			host, who := t.Host, c.author()
			c.DB.audit(c.U.Email, "fix.request-all", fmt.Sprintf("%s (%d)", t.Host, n))
			c.After = append(c.After, func() {
				go notifyStaff(fmt.Sprintf("Crimson: %s asked the team to fix %d problem(s) on %s", who, n, host))
			})
		}
		return map[string]int{"requested": n}, nil
	})

	s.handle("POST /api/targets/{id}/manual", "staff", true, func(c *Ctx) (any, error) {
		t, err := c.target(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		var in struct {
			Severity                Sev
			Title, Plain, Fix       string
			TitleAZ, PlainAZ, FixAZ string
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		if _, ok := sevRank[in.Severity]; !ok || strings.TrimSpace(in.Title) == "" || len(in.Title) > 200 || len(in.Plain) > 2000 || len(in.Fix) > 2000 {
			return nil, fail(400, "severity and a title are required")
		}
		en := tx(in.Title, in.Plain, in.Fix)
		az := en
		if strings.TrimSpace(in.TitleAZ) != "" {
			az = tx(in.TitleAZ, in.PlainAZ, in.FixAZ)
		}
		now := time.Now()
		f := &Finding{ID: newID("f"), TargetID: t.ID, Key: "manual|" + newID("m"), CheckID: "manual", Category: "manual",
			Severity: in.Severity, Evidence: "Found during manual review by " + c.author(), I18n: pair(en, az),
			Status: "open", Present: true, Manual: true, FirstSeen: now, LastSeen: now, Updated: now}
		c.DB.Findings[f.ID] = f
		c.DB.audit(c.U.Email, "finding.manual", t.Host+" — "+in.Title)
		return f, nil
	})

	s.handle("POST /api/targets/{id}/checklist/{key}", "staff", true, func(c *Ctx) (any, error) {
		t, err := c.target(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		var in struct {
			Done bool
			Note string
		}
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		for i := range t.Checklist {
			if t.Checklist[i].Key == c.R.PathValue("key") {
				ci := &t.Checklist[i]
				ci.Done, ci.Note, ci.By, ci.At = in.Done, in.Note, c.author(), time.Now()
				c.DB.audit(c.U.Email, "checklist", t.Host+" — "+ci.Key)
				return nil, nil
			}
		}
		return nil, fail(404, "unknown checklist item")
	})

	// ---- findings ----
	s.handle("POST /api/findings/{id}/request", "user", true, func(c *Ctx) (any, error) {
		f, t, err := c.finding(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		var in struct{ Requested bool }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		now := time.Now()
		switch {
		case in.Requested && f.Status == "open":
			f.Status = "requested"
			f.Comments = append(f.Comments, Comment{now, c.author(), c.U.Role, "Requested a fix for this problem."})
			host, who, title := t.Host, c.author(), f.I18n["en"].Title
			c.After = append(c.After, func() {
				go notifyStaff(fmt.Sprintf("Crimson: %s requested a fix on %s: %s", who, host, title))
			})
		case !in.Requested && f.Status == "requested":
			f.Status = "open"
			f.Comments = append(f.Comments, Comment{now, c.author(), c.U.Role, "Cancelled the fix request."})
		default:
			return nil, fail(409, "this problem cannot be changed from its current status")
		}
		f.Updated = now
		c.DB.audit(c.U.Email, "finding.request", t.Host+" — "+f.CheckID)
		return f, nil
	})

	s.handle("POST /api/findings/{id}/accept", "user", true, func(c *Ctx) (any, error) {
		f, t, err := c.finding(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		var in struct{ Accept bool }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		now := time.Now()
		switch {
		case in.Accept && (f.Status == "open" || f.Status == "requested"):
			f.Status = "accepted"
			f.Comments = append(f.Comments, Comment{now, c.author(), c.U.Role, "Accepted the risk; no fix wanted."})
		case !in.Accept && f.Status == "accepted":
			f.Status = "open"
			f.Comments = append(f.Comments, Comment{now, c.author(), c.U.Role, "Reopened this problem."})
		default:
			return nil, fail(409, "this problem cannot be changed from its current status")
		}
		f.Updated = now
		c.DB.audit(c.U.Email, "finding.accept", t.Host+" — "+f.CheckID)
		return f, nil
	})

	s.handle("POST /api/findings/{id}/comment", "user", true, func(c *Ctx) (any, error) {
		f, t, err := c.finding(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		var in struct{ Text string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		txt := strings.TrimSpace(in.Text)
		if txt == "" || len(txt) > 2000 {
			return nil, fail(400, "write a comment (max 2000 characters)")
		}
		f.Comments = append(f.Comments, Comment{time.Now(), c.author(), c.U.Role, txt})
		f.Updated = time.Now()
		if !c.staff() {
			host, who := t.Host, c.author()
			c.After = append(c.After, func() { go notifyStaff(fmt.Sprintf("Crimson: new comment from %s on %s", who, host)) })
		}
		return f, nil
	})

	s.handle("POST /api/findings/{id}/status", "staff", true, func(c *Ctx) (any, error) {
		f, t, err := c.finding(c.R.PathValue("id"))
		if err != nil {
			return nil, err
		}
		var in struct{ Status, Note string }
		if err := c.Bind(&in); err != nil {
			return nil, err
		}
		if !validStatus[in.Status] || len(in.Note) > 2000 {
			return nil, fail(400, "invalid status")
		}
		now := time.Now()
		text := "Status: " + in.Status
		if n := strings.TrimSpace(in.Note); n != "" {
			text += ". " + n
		}
		f.Status, f.Updated = in.Status, now
		f.Comments = append(f.Comments, Comment{now, c.author(), "staff", text})
		c.DB.audit(c.U.Email, "finding.status", fmt.Sprintf("%s — %s → %s", t.Host, f.CheckID, in.Status))
		return f, nil
	})

	s.handleRaw("POST /api/findings/{id}/explain", "user", s.explainHandler)

	// ---- staff ----
	s.handle("GET /api/staff/queue", "staff", false, func(c *Ctx) (any, error) {
		type item struct {
			FindingID string          `json:"findingId"`
			TargetID  string          `json:"targetId"`
			Host      string          `json:"host"`
			Org       string          `json:"org"`
			Sector    string          `json:"sector"`
			Severity  Sev             `json:"severity"`
			Status    string          `json:"status"`
			I18n      map[string]Text `json:"i18n"`
			Updated   time.Time       `json:"updated"`
			Manual    bool            `json:"manual"`
		}
		order := map[string]int{"requested": 0, "in_progress": 1, "fixed": 2}
		items := []item{}
		for _, f := range c.DB.Findings {
			if _, ok := order[f.Status]; !ok {
				continue
			}
			t := c.DB.Targets[f.TargetID]
			if t == nil {
				continue
			}
			org := c.DB.Orgs[t.OrgID]
			items = append(items, item{f.ID, t.ID, t.Host, org.Name, org.Sector, f.Severity, f.Status, f.I18n, f.Updated, f.Manual})
		}
		sort.Slice(items, func(i, j int) bool {
			a, b := items[i], items[j]
			if order[a.Status] != order[b.Status] {
				return order[a.Status] < order[b.Status]
			}
			if sevRank[a.Severity] != sevRank[b.Severity] {
				return sevRank[a.Severity] < sevRank[b.Severity]
			}
			return a.Updated.Before(b.Updated)
		})
		type pending struct {
			TargetID string `json:"targetId"`
			Host     string `json:"host"`
			Org      string `json:"org"`
		}
		pend := []pending{}
		for _, t := range c.DB.Targets {
			if !t.Verified {
				pend = append(pend, pending{t.ID, t.Host, c.DB.Orgs[t.OrgID].Name})
			}
		}
		return map[string]any{"items": items, "pending": pend, "orgs": len(c.DB.Orgs), "targets": len(c.DB.Targets)}, nil
	})

	s.handle("GET /api/staff/audit", "staff", false, func(c *Ctx) (any, error) {
		n := len(c.DB.Audit)
		out := make([]AuditEntry, 0, 100)
		for i := n - 1; i >= 0 && len(out) < 100; i-- {
			out = append(out, c.DB.Audit[i])
		}
		return out, nil
	})

	s.mux.HandleFunc("GET /report/{id}", s.reportHandler)
}

func meView(db *DB, u *User) map[string]any {
	user := map[string]any{"id": u.ID, "email": u.Email, "name": u.Name, "role": u.Role}
	if o := db.Orgs[u.OrgID]; o != nil {
		user["org"] = map[string]string{"id": o.ID, "name": o.Name, "sector": o.Sector}
	}
	return map[string]any{"user": user}
}

// ---- background scan -----------------------------------------------------------

func (s *Server) runScan(scanID, targetID string, o ScanOptions) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	o.Guard = s.guard
	if s.cfg.Sandbox && o.Host == "127.0.0.1" && o.Port == 8081 { // the bundled demo clinic only
		o.Guard = &Guard{AllowPrivate: true, Timeout: 2 * time.Second}
	}
	o.Progress = func(m string) {
		_ = s.store.Update(func(db *DB) error {
			if sc := db.Scans[scanID]; sc != nil {
				sc.Log = append(sc.Log, time.Now().Format("15:04:05")+"  "+m)
			}
			return nil
		})
	}
	res, scanErr := RunScan(ctx, o)

	var host, orgName string
	var newCrit, newHigh, score int
	var grade string
	_ = s.store.Update(func(db *DB) error {
		sc, t := db.Scans[scanID], db.Targets[targetID]
		if sc == nil || t == nil {
			return nil
		}
		host, orgName = t.Host, db.Orgs[t.OrgID].Name
		before := map[string]bool{}
		for _, f := range db.targetFindings(t.ID) {
			before[f.Key] = true
		}
		db.mergeScan(t, sc, res, scanErr)
		for _, f := range db.targetFindings(t.ID) {
			if !before[f.Key] {
				switch f.Severity {
				case SevCritical:
					newCrit++
				case SevHigh:
					newHigh++
				}
			}
		}
		score, grade = sc.Score, sc.Grade
		db.audit(sc.By, "scan.finish", fmt.Sprintf("%s — %s", t.Host, sc.Status))
		return nil
	})
	if scanErr == nil && (newCrit+newHigh) > 0 {
		notifyStaff(fmt.Sprintf("Crimson: scan of %s (%s) finished — score %d (%s). New critical: %d, new high: %d",
			host, orgName, score, grade, newCrit, newHigh))
	}
}

func (db *DB) mergeScan(t *Target, sc *Scan, res *ScanResult, scanErr error) {
	now := time.Now()
	t.Scanning = false
	sc.Finished = now
	if scanErr != nil {
		sc.Status, sc.Error = "failed", scanErr.Error()
		sc.Log = append(sc.Log, now.Format("15:04:05")+"  Scan failed: "+scanErr.Error())
		return
	}
	existing := map[string]*Finding{}
	for _, f := range db.targetFindings(t.ID) {
		if !f.Manual {
			existing[f.Key] = f
		}
	}
	seen := map[string]bool{}
	for _, rf := range res.Findings {
		seen[rf.Key] = true
		if f := existing[rf.Key]; f != nil {
			f.LastSeen, f.Severity, f.Evidence, f.I18n, f.Present = now, rf.Severity, rf.Evidence, rf.I18n, true
			switch f.Status {
			case "fixed", "verified", "resolved":
				f.Status, f.Updated = "open", now
				f.Comments = append(f.Comments, Comment{now, "Crimson scanner", "system", "The problem was detected again by the rescan; status reset to open."})
				sc.Reopened++
			}
			continue
		}
		f := &Finding{ID: newID("f"), TargetID: t.ID, Key: rf.Key, CheckID: rf.CheckID, Category: rf.Category,
			Severity: rf.Severity, Evidence: rf.Evidence, I18n: rf.I18n, Status: "open", Present: true,
			FirstSeen: now, LastSeen: now, Updated: now}
		db.Findings[f.ID] = f
		sc.New++
	}
	for key, f := range existing {
		if seen[key] || !f.Present || !res.Completed[f.Category] {
			continue
		}
		f.Present = false
		switch f.Status {
		case "fixed":
			f.Status, f.Updated = "verified", now
			f.Comments = append(f.Comments, Comment{now, "Crimson scanner", "system", "Confirmed fixed: the rescan no longer detects this problem."})
			sc.Resolved++
		case "open", "requested", "in_progress":
			f.Status, f.Updated = "resolved", now
			f.Comments = append(f.Comments, Comment{now, "Crimson scanner", "system", "No longer detected by the scan."})
			sc.Resolved++
		}
	}
	sc.Ports = res.OpenPorts
	sc.Score, sc.Grade, sc.Counts = scoreOf(db.targetFindings(t.ID))
	sc.Status = "done"
}

// ---- ownership verification ------------------------------------------------------

func (s *Server) verifyOwnership(ctx context.Context, host string, port int, token string) (string, bool) {
	if net.ParseIP(host) == nil {
		cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		txts, _ := net.DefaultResolver.LookupTXT(cctx, host)
		cancel()
		for _, t := range txts {
			if strings.Contains(t, "crimson-verify="+token) {
				return "dns", true
			}
		}
	}
	client := newHTTPClient(s.guard)
	for _, scheme := range []string{"https", "http"} {
		base := scheme + "://" + canonicalTarget(host, port)
		resp, body, err := httpGet(ctx, client, base+"/.well-known/crimson-verify.txt", 4<<10)
		if err == nil && resp.StatusCode == 200 && strings.Contains(string(body), token) {
			return "file", true
		}
	}
	return "", false
}

func (s *Server) verifyHandler(w http.ResponseWriter, r *http.Request, u User) {
	var host, token string
	var port int
	var already bool
	err := s.store.View(func(db *DB) error {
		t := db.Targets[r.PathValue("id")]
		if t == nil || (u.Role != "staff" && t.OrgID != u.OrgID) {
			return fail(404, "not found")
		}
		already, token = t.Verified, t.Token
		var perr error
		host, port, perr = parseTarget(t.Host)
		return perr
	})
	if err != nil {
		replyError(w, err)
		return
	}
	if already {
		writeJSON(w, 200, map[string]any{"verified": true})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	method, ok := s.verifyOwnership(ctx, host, port, token)
	if !ok {
		writeJSON(w, 200, map[string]any{"verified": false})
		return
	}
	_ = s.store.Update(func(db *DB) error {
		if t := db.Targets[r.PathValue("id")]; t != nil {
			t.Verified, t.VerifiedBy, t.VerifiedAt = true, method, time.Now()
			db.audit(u.Email, "target.verified", t.Host+" via "+method)
		}
		return nil
	})
	writeJSON(w, 200, map[string]any{"verified": true, "method": method})
}

func (s *Server) explainHandler(w http.ResponseWriter, r *http.Request, u User) {
	var in struct{ Lang string }
	body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	_ = json.Unmarshal(body, &in)
	if in.Lang != "az" {
		in.Lang = "en"
	}
	var f Finding
	var sector string
	err := s.store.View(func(db *DB) error {
		x := db.Findings[r.PathValue("id")]
		if x == nil {
			return fail(404, "not found")
		}
		t := db.Targets[x.TargetID]
		if t == nil || (u.Role != "staff" && t.OrgID != u.OrgID) {
			return fail(404, "not found")
		}
		f, sector = *x, db.Orgs[t.OrgID].Sector
		return nil
	})
	if err != nil {
		replyError(w, err)
		return
	}
	if txt := f.AI[in.Lang]; txt != "" {
		writeJSON(w, 200, map[string]string{"text": txt})
		return
	}
	if s.cfg.AnthropicKey == "" {
		writeErr(w, 501, "AI explanations are not configured on this server (set ANTHROPIC_API_KEY)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	txt, err := explainWithClaude(ctx, s.cfg.AnthropicKey, s.cfg.AnthropicModel, &f, sector, in.Lang)
	if err != nil {
		log.Printf("explain: %v", err)
		writeErr(w, 502, "the AI service is unavailable right now")
		return
	}
	_ = s.store.Update(func(db *DB) error {
		if x := db.Findings[f.ID]; x != nil {
			if x.AI == nil {
				x.AI = map[string]string{}
			}
			x.AI[in.Lang] = txt
		}
		return nil
	})
	writeJSON(w, 200, map[string]string{"text": txt})
}

// ---- bootstrap helpers ---------------------------------------------------------

func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr: s.cfg.Addr, Handler: s.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 90 * time.Second, IdleTimeout: 120 * time.Second,
	}
	return srv.ListenAndServe()
}

func ensureStaff(store *Store, email, password, name string) (created bool, err error) {
	err = store.Update(func(db *DB) error {
		for _, u := range db.Users {
			if u.Email == strings.ToLower(email) {
				return nil
			}
		}
		u := newUser(email, name, "staff", "", password)
		db.Users[u.ID] = u
		created = true
		return nil
	})
	return
}

func seedDemo(store *Store) error {
	return store.Update(func(db *DB) error {
		for _, u := range db.Users {
			if u.Email == "demo@sunriseclinic.example" {
				return nil
			}
		}
		org := &Org{ID: newID("o"), Name: "Sunrise Clinic", Sector: "healthcare", Created: time.Now()}
		db.Orgs[org.ID] = org
		u := newUser("demo@sunriseclinic.example", "Demo Customer", "customer", org.ID, "Demo-Crimson-2026!")
		db.Users[u.ID] = u
		t := &Target{ID: newID("t"), OrgID: org.ID, Host: "127.0.0.1:8081", Token: randomHex(10), Verified: true,
			VerifiedBy: "local-dev-mode", VerifiedAt: time.Now(), Created: time.Now(), Checklist: seedChecklist(org.Sector)}
		db.Targets[t.ID] = t
		return nil
	})
}

func mustEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var _ = bytes.MinRead
