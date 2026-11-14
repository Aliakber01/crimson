package main

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"sort"
	"time"
)

// The report is a self-contained, print-ready page: a customer opens it and uses
// "Print -> Save as PDF". No PDF library, no dependencies, works offline.

var reportStrings = map[string]map[string]string{
	"en": {
		"title": "Security report", "score": "Security score", "summary": "Summary",
		"open": "open problems", "fixedLine": "fixed and verified", "findings": "Findings",
		"fix": "How to fix", "evidence": "Evidence", "status": "Status", "manual": "Manual review by the Crimson team",
		"none": "No problems are currently open. Well done.", "print": "Print / Save as PDF",
		"disc":      "This report covers what an external scan and the Crimson team's manual review could observe on the date shown. It is not a guarantee that no other weaknesses exist.",
		"generated": "Generated", "sector": "Sector", "site": "Target",
		"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info",
		"open_": "Open", "requested": "Fix requested", "in_progress": "In progress", "fixed": "Fixed, awaiting check",
		"verified": "Verified fixed", "resolved": "No longer detected", "accepted": "Risk accepted",
		"done": "done", "of": "of",
	},
	"az": {
		"title": "Təhlükəsizlik hesabatı", "score": "Təhlükəsizlik balı", "summary": "Xülasə",
		"open": "açıq problem", "fixedLine": "düzəldilib və təsdiqlənib", "findings": "Tapıntılar",
		"fix": "Necə düzəltməli", "evidence": "Sübut", "status": "Status", "manual": "Crimson komandasının əl ilə yoxlaması",
		"none": "Hazırda açıq problem yoxdur. Əla!", "print": "Çap et / PDF kimi saxla",
		"disc":      "Bu hesabat göstərilən tarixdə xarici skan və Crimson komandasının əl ilə yoxlaması ilə görünə bilən məsələləri əhatə edir. Başqa zəifliklərin olmadığına zəmanət deyil.",
		"generated": "Hazırlanıb", "sector": "Sahə", "site": "Hədəf",
		"critical": "Kritik", "high": "Yüksək", "medium": "Orta", "low": "Aşağı", "info": "Məlumat",
		"open_": "Açıq", "requested": "Düzəliş istənilib", "in_progress": "İcrada", "fixed": "Düzəldilib, yoxlama gözlənilir",
		"verified": "Düzəliş təsdiqlənib", "resolved": "Artıq aşkarlanmır", "accepted": "Risk qəbul edilib",
		"done": "tamamlanıb", "of": "/",
	},
}

type reportFinding struct {
	Sev, SevLabel, Status, StatusLabel, Title, Plain, Fix, Evidence string
	Active                                                          bool
}

type reportCheck struct {
	Done  bool
	Label string
	Note  string
}

type reportData struct {
	L          map[string]string
	Lang       string
	Nonce      string
	Org, Host  string
	Sector     string
	Date       string
	Score      int
	Grade      string
	OpenCount  int
	FixedCount int
	Counts     []struct {
		Label, Sev string
		N          int
	}
	Active     []reportFinding
	Closed     []reportFinding
	Checklist  []reportCheck
	CheckDone  int
	CheckTotal int
}

func (s *Server) reportHandler(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang != "az" {
		lang = "en"
	}
	L := reportStrings[lang]
	var d reportData
	var denied bool
	_ = s.store.View(func(db *DB) error {
		u := userFromRequest(db, r)
		t := db.Targets[r.PathValue("id")]
		if u == nil || t == nil || (u.Role != "staff" && t.OrgID != u.OrgID) {
			denied = true
			return nil
		}
		org := db.Orgs[t.OrgID]
		fs := db.targetFindings(t.ID)
		sortFindings(fs)
		score, grade, counts := scoreOf(fs)
		d = reportData{L: L, Lang: lang, Org: org.Name, Host: t.Host, Sector: org.Sector,
			Date: time.Now().Format("2006-01-02 15:04"), Score: score, Grade: grade}
		for _, sv := range []Sev{SevCritical, SevHigh, SevMedium, SevLow} {
			d.Counts = append(d.Counts, struct {
				Label, Sev string
				N          int
			}{L[string(sv)], string(sv), counts[sv]})
		}
		statusKey := map[string]string{"open": "open_"}
		for _, f := range fs {
			if !f.Present && !f.Manual && f.Status == "accepted" {
				continue
			}
			tx, ok := f.I18n[lang]
			if !ok {
				tx = f.I18n["en"]
			}
			sk := f.Status
			if k, ok := statusKey[sk]; ok {
				sk = k
			}
			rf := reportFinding{Sev: string(f.Severity), SevLabel: L[string(f.Severity)], Status: f.Status,
				StatusLabel: L[sk], Title: tx.Title, Plain: tx.Plain, Fix: tx.Fix, Evidence: f.Evidence, Active: isActive(f)}
			if rf.Active {
				d.Active = append(d.Active, rf)
				d.OpenCount++
			} else if f.Status == "verified" || f.Status == "resolved" || f.Status == "fixed" {
				d.Closed = append(d.Closed, rf)
				d.FixedCount++
			} else {
				d.Closed = append(d.Closed, rf)
			}
		}
		sort.SliceStable(d.Closed, func(i, j int) bool { return d.Closed[i].Title < d.Closed[j].Title })
		for _, ci := range t.Checklist {
			l := checklistCatalog[ci.Key]
			lab := l.EN
			if lang == "az" {
				lab = l.AZ
			}
			d.Checklist = append(d.Checklist, reportCheck{Done: ci.Done, Label: lab, Note: ci.Note})
			if ci.Done {
				d.CheckDone++
			}
		}
		d.CheckTotal = len(t.Checklist)
		return nil
	})
	if denied {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	nb := make([]byte, 16)
	_, _ = rand.Read(nb)
	d.Nonce = base64.StdEncoding.EncodeToString(nb)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+d.Nonce+"'; frame-ancestors 'none'; base-uri 'none'")
	_ = reportTpl.Execute(w, d)
}

var reportTpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Crimson — {{.L.title}} — {{.Host}}</title>
<style>
:root{--crimson:#c8102e;--ink:#17171c;--muted:#5f6068;--line:#e3e3e8;--bg:#fff}
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:#f3f3f6}
.page{max-width:860px;margin:24px auto;background:var(--bg);padding:48px 52px;box-shadow:0 2px 24px rgba(0,0,0,.08)}
header{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid var(--crimson);padding-bottom:18px;margin-bottom:26px}
.brand{font-weight:800;letter-spacing:.22em;color:var(--crimson);font-size:15px}
h1{margin:6px 0 2px;font-size:26px}
.meta{color:var(--muted);font-size:13px}
.btn{border:1px solid var(--line);background:#fff;padding:8px 14px;border-radius:8px;cursor:pointer;font:inherit}
.grid{display:grid;grid-template-columns:150px 1fr;gap:28px;align-items:center;margin:8px 0 30px}
.score{width:140px;height:140px;border-radius:50%;border:10px solid var(--crimson);display:flex;flex-direction:column;align-items:center;justify-content:center}
.score b{font-size:44px;line-height:1}.score span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.chip{border:1px solid var(--line);border-radius:999px;padding:4px 12px;font-size:13px}
.chip i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.critical{--c:#d6103a}.high{--c:#e8761c}.medium{--c:#d9a400}.low{--c:#2f7fd1}.info{--c:#777}
.chip i,.tag{background:var(--c)}
h2{font-size:18px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.f{border:1px solid var(--line);border-left:5px solid var(--c);border-radius:8px;padding:14px 18px;margin:12px 0;break-inside:avoid}
.f h3{margin:0 0 6px;font-size:16px}
.tag{color:#fff;font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:2px 8px;border-radius:4px;margin-right:8px}
.st{float:right;font-size:12px;color:var(--muted)}
.f p{margin:6px 0}.fix{background:#f6f6f9;border-radius:6px;padding:8px 12px;margin-top:8px}
.ev{font:12px ui-monospace,Menlo,Consolas,monospace;color:var(--muted);margin-top:6px}
.closed .f{opacity:.8}
ul.check{list-style:none;padding:0;margin:0}ul.check li{padding:5px 0;border-bottom:1px dashed var(--line)}
.box{display:inline-block;width:18px;font-weight:700}.ok{color:#18975c}.no{color:#a9a9b3}
.disc{margin-top:36px;font-size:12px;color:var(--muted);border-top:1px solid var(--line);padding-top:12px}
@media print{body{background:#fff}.page{box-shadow:none;margin:0;padding:0}.btn{display:none}}
</style></head><body><div class="page">
<header><div><div class="brand">CRIMSON</div><h1>{{.L.title}}</h1>
<div class="meta">{{.Org}} · {{.L.site}}: {{.Host}} · {{.L.sector}}: {{.Sector}}<br>{{.L.generated}}: {{.Date}}</div></div>
<button class="btn" id="p">{{.L.print}}</button></header>

<div class="grid"><div class="score"><b>{{.Grade}}</b><span>{{.Score}} / 100</span></div>
<div><h2 style="margin:0;border:0">{{.L.summary}}</h2>
<p style="margin:6px 0">{{.OpenCount}} {{.L.open}} · {{.FixedCount}} {{.L.fixedLine}}</p>
<div class="chips">{{range .Counts}}<span class="chip {{.Sev}}"><i></i>{{.Label}}: {{.N}}</span>{{end}}</div></div></div>

<h2>{{.L.findings}}</h2>
{{if not .Active}}<p>{{.L.none}}</p>{{end}}
{{range .Active}}<div class="f {{.Sev}}"><span class="st">{{.StatusLabel}}</span><h3><span class="tag">{{.SevLabel}}</span>{{.Title}}</h3>
<p>{{.Plain}}</p><div class="fix"><b>{{$.L.fix}}:</b> {{.Fix}}</div><div class="ev">{{$.L.evidence}}: {{.Evidence}}</div></div>{{end}}

{{if .Closed}}<div class="closed"><h2>✓</h2>
{{range .Closed}}<div class="f {{.Sev}}"><span class="st">{{.StatusLabel}}</span><h3><span class="tag">{{.SevLabel}}</span>{{.Title}}</h3></div>{{end}}</div>{{end}}

<h2>{{.L.manual}} — {{.CheckDone}} {{.L.of}} {{.CheckTotal}} {{.L.done}}</h2>
<ul class="check">{{range .Checklist}}<li><span class="box {{if .Done}}ok{{else}}no{{end}}">{{if .Done}}✓{{else}}○{{end}}</span>{{.Label}}{{if .Note}} <span class="meta">— {{.Note}}</span>{{end}}</li>{{end}}</ul>
<p class="disc">{{.L.disc}}</p></div>
<script nonce="{{.Nonce}}">document.getElementById('p').addEventListener('click',function(){window.print()})</script>
</body></html>`))
