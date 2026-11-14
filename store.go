package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ---- data model ----------------------------------------------------------------

type User struct {
	ID      string    `json:"id"`
	Email   string    `json:"email"`
	Name    string    `json:"name"`
	Role    string    `json:"role"` // customer | staff
	OrgID   string    `json:"orgId,omitempty"`
	Salt    []byte    `json:"salt"`
	Hash    []byte    `json:"hash"`
	Created time.Time `json:"created"`
}

type Org struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Sector  string    `json:"sector"`
	Created time.Time `json:"created"`
}

type ChecklistItem struct {
	Key  string    `json:"key"`
	Done bool      `json:"done"`
	Note string    `json:"note,omitempty"`
	By   string    `json:"by,omitempty"`
	At   time.Time `json:"at,omitempty"`
}

type Target struct {
	ID         string          `json:"id"`
	OrgID      string          `json:"orgId"`
	Host       string          `json:"host"`
	Token      string          `json:"token"`
	Verified   bool            `json:"verified"`
	VerifiedBy string          `json:"verifiedBy,omitempty"`
	VerifiedAt time.Time       `json:"verifiedAt,omitempty"`
	Scanning   bool            `json:"scanning"`
	LastScanID string          `json:"lastScanId,omitempty"`
	Checklist  []ChecklistItem `json:"checklist"`
	Created    time.Time       `json:"created"`
}

type Scan struct {
	ID       string      `json:"id"`
	TargetID string      `json:"targetId"`
	Started  time.Time   `json:"started"`
	Finished time.Time   `json:"finished,omitempty"`
	Status   string      `json:"status"` // running | done | failed
	Error    string      `json:"error,omitempty"`
	Deep     bool        `json:"deep"`
	By       string      `json:"by"`
	Ports    []int       `json:"openPorts"`
	Score    int         `json:"score"`
	Grade    string      `json:"grade"`
	Counts   map[Sev]int `json:"counts"`
	New      int         `json:"new"`
	Reopened int         `json:"reopened"`
	Resolved int         `json:"resolved"`
	Log      []string    `json:"log"`
}

type Comment struct {
	At   time.Time `json:"at"`
	By   string    `json:"by"`
	Role string    `json:"role"` // customer | staff | system
	Text string    `json:"text"`
}

// Finding lives at target level and survives between scans: that is what makes
// "requested -> in progress -> fixed -> verified by rescan" possible.
type Finding struct {
	ID        string            `json:"id"`
	TargetID  string            `json:"targetId"`
	Key       string            `json:"key"`
	CheckID   string            `json:"checkId"`
	Category  string            `json:"category"`
	Severity  Sev               `json:"severity"`
	Evidence  string            `json:"evidence"`
	I18n      map[string]Text   `json:"i18n"`
	Status    string            `json:"status"` // open requested in_progress fixed verified resolved accepted
	Present   bool              `json:"present"`
	Manual    bool              `json:"manual"`
	FirstSeen time.Time         `json:"firstSeen"`
	LastSeen  time.Time         `json:"lastSeen"`
	Updated   time.Time         `json:"updated"`
	Comments  []Comment         `json:"comments"`
	AI        map[string]string `json:"ai,omitempty"`
}

type Session struct {
	UserID  string    `json:"userId"`
	Expires time.Time `json:"expires"`
}

type AuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

type Reset struct {
	UserID  string    `json:"userId"`
	Expires time.Time `json:"expires"`
}

type DB struct {
	Users    map[string]*User    `json:"users"`
	Orgs     map[string]*Org     `json:"orgs"`
	Targets  map[string]*Target  `json:"targets"`
	Scans    map[string]*Scan    `json:"scans"`
	Findings map[string]*Finding `json:"findings"`
	Sessions map[string]*Session `json:"sessions"`
	Resets   map[string]*Reset   `json:"resets"`
	Audit    []AuditEntry        `json:"audit"`
}

func newDB() *DB {
	return &DB{
		Users: map[string]*User{}, Orgs: map[string]*Org{}, Targets: map[string]*Target{},
		Scans: map[string]*Scan{}, Findings: map[string]*Finding{}, Sessions: map[string]*Session{}, Resets: map[string]*Reset{},
	}
}

// ---- store ---------------------------------------------------------------------

// Store is a small JSON-file database: one process, one mutex, atomic writes.
// It keeps the hackathon build dependency-free (no cgo, no external DB); the
// interface (View/Update) is narrow so it can be swapped for SQLite or Postgres later.
type Store struct {
	mu   sync.RWMutex
	path string
	db   *DB
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, db: newDB()}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, s.db); err != nil {
			return nil, err
		}
		if s.db.Users == nil || s.db.Sessions == nil || s.db.Findings == nil {
			return nil, errors.New("database file is corrupt")
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}
	if s.db.Resets == nil {
		s.db.Resets = map[string]*Reset{}
	}
	// a restart interrupts running scans; do not leave them hanging forever
	for _, sc := range s.db.Scans {
		if sc.Status == "running" {
			sc.Status, sc.Error, sc.Finished = "failed", "interrupted by server restart", time.Now()
		}
	}
	for _, t := range s.db.Targets {
		t.Scanning = false
	}
	return s, nil
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.db, "", " ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(s.path), "."+filepath.Base(s.path)+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) View(fn func(*DB) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fn(s.db)
}

func (s *Store) Update(fn func(*DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.db); err != nil {
		return err
	}
	return s.save()
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (db *DB) audit(actor, action, detail string) {
	db.Audit = append(db.Audit, AuditEntry{At: time.Now(), Actor: actor, Action: action, Detail: detail})
	if len(db.Audit) > 1000 {
		db.Audit = db.Audit[len(db.Audit)-1000:]
	}
}

// ---- scoring -------------------------------------------------------------------

// isActive: does this finding still count against the organisation right now?
// "fixed" is excluded on purpose: the engineer says it is done; a rescan will re-open it if not.
func isActive(f *Finding) bool {
	switch f.Status {
	case "verified", "resolved", "accepted", "fixed":
		return false
	}
	return f.Present || f.Manual
}

var penalty = map[Sev]int{SevCritical: 25, SevHigh: 12, SevMedium: 5, SevLow: 2, SevInfo: 0}

func scoreOf(findings []*Finding) (int, string, map[Sev]int) {
	score := 100
	counts := map[Sev]int{}
	for _, f := range findings {
		if isActive(f) {
			score -= penalty[f.Severity]
			counts[f.Severity]++
		}
	}
	if score < 0 {
		score = 0
	}
	g := "F"
	switch {
	case score >= 90:
		g = "A"
	case score >= 80:
		g = "B"
	case score >= 65:
		g = "C"
	case score >= 50:
		g = "D"
	}
	return score, g, counts
}

func (db *DB) targetFindings(targetID string) []*Finding {
	var out []*Finding
	for _, f := range db.Findings {
		if f.TargetID == targetID {
			out = append(out, f)
		}
	}
	return out
}

// ---- manual-review checklist ---------------------------------------------------

type L2 struct {
	EN      string   `json:"en"`
	AZ      string   `json:"az"`
	Sectors []string `json:"-"` // empty = every sector
}

// These are the things an external scanner can never see. A human on the Crimson team
// works through them with the customer and ticks them off.
var checklistCatalog = map[string]L2{
	"internal_scan": {EN: "Internal network reviewed: device inventory, open shares, default passwords", AZ: "Daxili şəbəkə yoxlanıb: cihaz siyahısı, açıq paylaşımlar, standart parollar"},
	"mfa":           {EN: "Multi-factor authentication on e-mail, VPN and administrator accounts", AZ: "E-poçt, VPN və administrator hesablarında çoxfaktorlu autentifikasiya (MFA)"},
	"backups":       {EN: "Backups exist, are offline or immutable, and a restore was tested in the last 3 months", AZ: "Ehtiyat nüsxələr mövcuddur, oflayn/dəyişilməzdir və son 3 ayda bərpa sınaqdan keçirilib"},
	"patching":      {EN: "Servers, laptops and network devices receive security updates on a schedule", AZ: "Server, noutbuk və şəbəkə cihazları cədvəl üzrə təhlükəsizlik yeniləmələri alır"},
	"accounts":      {EN: "No shared admin accounts; access of former staff removed", AZ: "Paylaşılan admin hesabı yoxdur; keçmiş işçilərin girişi silinib"},
	"endpoint":      {EN: "Endpoint protection (antivirus / EDR) installed on every computer", AZ: "Bütün kompüterlərdə endpoint qoruması (antivirus / EDR) quraşdırılıb"},
	"wifi":          {EN: "Office Wi-Fi uses WPA2/WPA3 and guests are on a separate network", AZ: "Ofis Wi-Fi-ı WPA2/WPA3 işlədir, qonaqlar ayrıca şəbəkədədir"},
	"cloud":         {EN: "Cloud and SaaS accounts reviewed: public storage, sharing links, old users", AZ: "Bulud və SaaS hesabları yoxlanıb: açıq yaddaş, paylaşım linkləri, köhnə istifadəçilər"},
	"phishing":      {EN: "Staff received phishing-awareness training", AZ: "İşçilər fişinq barədə maarifləndirmə təlimi alıb"},
	"ir_plan":       {EN: "Incident-response plan and emergency contacts exist", AZ: "Insident reaksiya planı və təcili əlaqə siyahısı mövcuddur"},
	"ehr_access":    {EN: "Patient-record system access is role-based and logged", AZ: "Xəstə qeydləri sisteminə giriş rol əsaslıdır və jurnallaşdırılır", Sectors: []string{"healthcare"}},
	"device_seg":    {EN: "Medical devices (imaging, monitors, pumps) are on a segmented network", AZ: "Tibbi cihazlar (görüntüləmə, monitorlar, nasoslar) ayrıca şəbəkə seqmentindədir", Sectors: []string{"healthcare"}},
	"dicom_auth":    {EN: "DICOM / HL7 endpoints require authentication and encryption", AZ: "DICOM / HL7 nöqtələri autentifikasiya və şifrələmə tələb edir", Sectors: []string{"healthcare"}},
	"downtime":      {EN: "Downtime procedure for clinical systems tested (paper fallback)", AZ: "Klinik sistemlər üçün dayanma prosedurunun (kağız ehtiyatı) sınağı keçirilib", Sectors: []string{"healthcare"}},
	"vendor_access": {EN: "Vendor and remote-support access to clinical systems is controlled", AZ: "Klinik sistemlərə podratçı və uzaqdan dəstək girişi nəzarətdədir", Sectors: []string{"healthcare"}},
}

var checklistOrder = []string{"internal_scan", "mfa", "backups", "patching", "accounts", "endpoint", "wifi", "cloud", "phishing", "ir_plan",
	"ehr_access", "device_seg", "dicom_auth", "downtime", "vendor_access"}

func seedChecklist(sector string) []ChecklistItem {
	var out []ChecklistItem
	for _, k := range checklistOrder {
		l := checklistCatalog[k]
		ok := len(l.Sectors) == 0
		for _, s := range l.Sectors {
			if s == sector {
				ok = true
			}
		}
		if ok {
			out = append(out, ChecklistItem{Key: k})
		}
	}
	return out
}
