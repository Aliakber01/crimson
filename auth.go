package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "crimson_session"
	sessionTTL    = 7 * 24 * time.Hour
	pbkdf2Iter    = 210_000
)

func hashPassword(pw string, salt []byte) []byte {
	k, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		panic(err) // only possible for invalid parameters, which are constants here
	}
	return k
}

func newUser(email, name, role, orgID, password string) *User {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return &User{
		ID: newID("u"), Email: strings.ToLower(strings.TrimSpace(email)), Name: strings.TrimSpace(name),
		Role: role, OrgID: orgID, Salt: salt, Hash: hashPassword(password, salt), Created: time.Now(),
	}
}

// dummy keeps login timing similar whether or not the e-mail exists.
var dummySalt = make([]byte, 16)

func checkPassword(u *User, pw string) bool {
	if u == nil {
		hashPassword(pw, dummySalt)
		return false
	}
	return subtle.ConstantTimeCompare(hashPassword(pw, u.Salt), u.Hash) == 1
}

func sessionKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (db *DB) startSession(w http.ResponseWriter, r *http.Request, userID string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	now := time.Now()
	for k, s := range db.Sessions { // opportunistic cleanup
		if now.After(s.Expires) {
			delete(db.Sessions, k)
		}
	}
	db.Sessions[sessionKey(token)] = &Session{UserID: userID, Expires: now.Add(sessionTTL)}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: isHTTPS(r), Expires: now.Add(sessionTTL),
	})
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func clearSession(w http.ResponseWriter, r *http.Request, db *DB) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		delete(db.Sessions, sessionKey(ck.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isHTTPS(r)})
}

func userFromRequest(db *DB, r *http.Request) *User {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	s := db.Sessions[sessionKey(ck.Value)]
	if s == nil || time.Now().After(s.Expires) {
		return nil
	}
	return db.Users[s.UserID]
}

// rateLimiter: simple sliding window per client IP, enough to blunt password guessing.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: map[string][]time.Time{}, limit: limit, window: window}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	keep := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if now.Sub(t) < rl.window {
			keep = append(keep, t)
		}
	}
	if len(keep) >= rl.limit {
		rl.hits[key] = keep
		return false
	}
	rl.hits[key] = append(keep, now)
	return true
}

// trustProxy is set when Crimson runs behind a reverse proxy / platform router (Render, Fly, nginx ...).
// Only then is X-Forwarded-For used for rate limiting; otherwise clients could spoof it.
var trustProxy bool

func clientIP(r *http.Request) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
