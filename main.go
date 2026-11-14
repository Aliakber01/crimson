package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const banner = `
  ┏━╸┏━┓╻┏┳┓┏━┓┏━┓┏┓╻
  ┃  ┣┳┛┃┃┃┃┗━┓┃ ┃┃┗┫   security scanning for organisations without a security team
  ┗━╸╹┗╸╹╹ ╹┗━┛┗━┛╹ ╹`

func usage() {
	fmt.Println(banner)
	fmt.Print(`
Usage:
  crimson serve        [-addr 127.0.0.1:8080] [-data crimson-data.json] [-demo] [-sandbox] [-allow-private]
  crimson scan         [-sector healthcare] [-deep] [-json] [-authorized] <host[:port]>
  crimson user add     -role staff|customer -email you@x.com [-name "Name"] [-data file]
  crimson demo-target  [-addr 127.0.0.1:8081]
  crimson demo         one command: weak demo site + dashboard + opens your browser

Environment (or .env file):
  CRIMSON_STAFF_EMAIL / CRIMSON_STAFF_PASSWORD   first staff account
  ANTHROPIC_API_KEY, CRIMSON_AI_MODEL            optional AI explanations (default model claude-sonnet-5-5)
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID           optional staff notifications
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM   password-reset e-mail (link is printed to the console if unset)
  CRIMSON_BASE_URL                               public https URL used in e-mail links (RENDER_EXTERNAL_URL is picked up automatically)
  CRIMSON_SANDBOX=1                              public hosting mode (see DEPLOY.md)
`)
}

func main() {
	loadDotEnv(".env")
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "user":
		cmdUser(os.Args[2:])
	case "demo-target":
		cmdDemoTarget(os.Args[2:])
	case "demo":
		cmdDemo()
	default:
		usage()
		os.Exit(2)
	}
}

func cmdServe(args []string) {
	fl := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fl.String("addr", defaultAddr(), "listen address (hosting platforms set PORT)")
	data := fl.String("data", mustEnv("CRIMSON_DATA", "crimson-data.json"), "data file")
	demo := fl.Bool("demo", false, "seed demo accounts and allow scanning local addresses")
	sandbox := fl.Bool("sandbox", os.Getenv("CRIMSON_SANDBOX") == "1", "public hosting mode: demo accounts only, real systems need ownership proof")
	priv := fl.Bool("allow-private", false, "allow scanning private/loopback addresses (local testing only)")
	_ = fl.Parse(args)

	store, err := OpenStore(*data)
	if err != nil {
		fmt.Println("cannot open data file:", err)
		os.Exit(1)
	}
	model := mustEnv("CRIMSON_AI_MODEL", "claude-sonnet-5-5")
	baseURL := mustEnv("CRIMSON_BASE_URL", os.Getenv("RENDER_EXTERNAL_URL"))
	proxy := os.Getenv("CRIMSON_TRUST_PROXY") == "1" || os.Getenv("RENDER") == "true"
	if *sandbox {
		*demo, *priv = false, false // never allow private-network scanning on a public host
	}
	srv := NewServer(Config{Addr: *addr, DataPath: *data, AllowPrivate: *priv || *demo, Demo: *demo || *sandbox,
		Sandbox: *sandbox, SandboxSignup: os.Getenv("CRIMSON_SANDBOX_SIGNUP") == "1",
		BaseURL: baseURL, TrustProxy: proxy, Mail: mailerFromEnv(), SandboxHint: sandboxAccounts(*sandbox),
		AnthropicKey: os.Getenv("ANTHROPIC_API_KEY"), AnthropicModel: model}, store)

	fmt.Println(banner)
	if *sandbox {
		_ = seedDemo(store)
		email, pw := mustEnv("CRIMSON_STAFF_EMAIL", "staff@crimson.local"), mustEnv("CRIMSON_STAFF_PASSWORD", "Staff-Crimson-2026!")
		_, _ = ensureStaff(store, email, pw, "Crimson Analyst")
		go cmdDemoTarget(nil) // the weak clinic site the sandbox is allowed to scan (loopback only)
		time.Sleep(500 * time.Millisecond)
		fmt.Println("\n  PUBLIC SANDBOX — demo accounts only, real systems must prove ownership.")
		fmt.Println("  customer:  demo@sunriseclinic.example / Demo-Crimson-2026!")
		fmt.Println("  staff:     " + email + " / " + pw)
	} else if *demo {
		_ = seedDemo(store)
		created, _ := ensureStaff(store, "staff@crimson.local", "Staff-Crimson-2026!", "Crimson Analyst")
		_ = created
		fmt.Println("\n  DEMO MODE — fixed passwords, local scanning enabled. Never expose this to the internet.")
		fmt.Println("  customer:  demo@sunriseclinic.example / Demo-Crimson-2026!")
		fmt.Println("  staff:     staff@crimson.local / Staff-Crimson-2026!")
		fmt.Println("  weak site: crimson demo-target   (then scan 127.0.0.1:8081)")
	} else if email, pw := os.Getenv("CRIMSON_STAFF_EMAIL"), os.Getenv("CRIMSON_STAFF_PASSWORD"); email != "" && pw != "" {
		if created, err := ensureStaff(store, email, pw, "Crimson Team"); err == nil && created {
			fmt.Println("\n  staff account created:", email)
		}
	} else {
		hasStaff := false
		_ = store.View(func(db *DB) error {
			for _, u := range db.Users {
				if u.Role == "staff" {
					hasStaff = true
				}
			}
			return nil
		})
		if !hasStaff {
			fmt.Println("\n  No staff account yet. Create one with:  crimson user add -role staff -email you@x.com")
		}
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		fmt.Println("  AI explanations: on (" + model + ")")
	}
	fmt.Printf("\n  Dashboard: http://%s\n\n", *addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// defaultAddr: CRIMSON_ADDR if set, else :PORT (Render, Railway, Fly, Heroku ...), else loopback.
func defaultAddr() string {
	if a := os.Getenv("CRIMSON_ADDR"); a != "" {
		return a
	}
	if p := os.Getenv("PORT"); p != "" {
		return ":" + p
	}
	return "127.0.0.1:8080"
}

func cmdUser(args []string) {
	if len(args) == 0 || args[0] != "add" {
		usage()
		os.Exit(2)
	}
	fl := flag.NewFlagSet("user add", flag.ExitOnError)
	role := fl.String("role", "staff", "staff or customer")
	email := fl.String("email", "", "e-mail")
	name := fl.String("name", "", "display name")
	data := fl.String("data", mustEnv("CRIMSON_DATA", "crimson-data.json"), "data file")
	pw := fl.String("password", os.Getenv("CRIMSON_NEW_PASSWORD"), "password (or CRIMSON_NEW_PASSWORD)")
	_ = fl.Parse(args[1:])
	if *role != "staff" || *email == "" || len(*pw) < 10 {
		fmt.Println("need -role staff, -email, and a password of 10+ characters (-password or CRIMSON_NEW_PASSWORD)")
		os.Exit(2)
	}
	store, err := OpenStore(*data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	created, err := ensureStaff(store, *email, *pw, *name)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if created {
		fmt.Println("staff account created:", *email)
	} else {
		fmt.Println("an account with that e-mail already exists")
	}
}

func cmdScan(args []string) {
	fl := flag.NewFlagSet("scan", flag.ExitOnError)
	sector := fl.String("sector", "general", "sector (healthcare raises severity of medical-protocol exposure)")
	deep := fl.Bool("deep", false, "also run nuclei templates if installed")
	asJSON := fl.Bool("json", false, "print JSON")
	authorized := fl.Bool("authorized", false, "confirm you own the target or have written permission to test it")
	priv := fl.Bool("allow-private", false, "allow private/loopback targets")
	_ = fl.Parse(args)
	if fl.NArg() != 1 {
		usage()
		os.Exit(2)
	}
	host, port, err := parseTarget(fl.Arg(0))
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(2)
	}
	if !isLocalLiteral(host) && !*authorized {
		fmt.Println("Only scan systems you own or have written permission to test.")
		fmt.Println("Re-run with -authorized to confirm that you have that permission.")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	res, err := RunScan(ctx, ScanOptions{
		Host: host, Port: port, Sector: *sector, Deep: *deep,
		Guard:    &Guard{AllowPrivate: *priv || isLocalLiteral(host), Timeout: 2 * time.Second},
		Progress: func(m string) { fmt.Fprintln(os.Stderr, "  ·", m) },
	})
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	if *asJSON {
		out := make([]map[string]any, 0, len(res.Findings))
		for _, f := range res.Findings {
			out = append(out, map[string]any{"id": f.CheckID, "severity": f.Severity, "category": f.Category,
				"title": f.I18n["en"].Title, "evidence": f.Evidence, "fix": f.I18n["en"].Fix})
		}
		b, _ := json.MarshalIndent(map[string]any{"target": fl.Arg(0), "openPorts": res.OpenPorts, "findings": out}, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Println(banner)
	fmt.Printf("\n  Target: %s   open ports: %v\n\n", fl.Arg(0), res.OpenPorts)
	if len(res.Findings) == 0 {
		fmt.Println("  No problems found.")
	}
	for _, f := range res.Findings {
		fmt.Printf("  [%-8s] %s\n             %s\n             fix: %s\n\n",
			strings.ToUpper(string(f.Severity)), f.I18n["en"].Title, f.Evidence, f.I18n["en"].Fix)
	}
}

// cmdDemo starts the weak demo site and the dashboard in demo mode and opens the browser.
func cmdDemo() {
	go cmdDemoTarget(nil)
	time.Sleep(600 * time.Millisecond)
	go func() {
		time.Sleep(1200 * time.Millisecond)
		openBrowser("http://127.0.0.1:8080")
	}()
	cmdServe([]string{"-demo"})
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}

// sandboxAccounts lists the public demo logins shown on the sandbox sign-in screen.
func sandboxAccounts(on bool) []map[string]string {
	if !on {
		return nil
	}
	return []map[string]string{
		{"role": "customer", "email": "demo@sunriseclinic.example", "password": "Demo-Crimson-2026!"},
		{"role": "staff", "email": mustEnv("CRIMSON_STAFF_EMAIL", "staff@crimson.local"), "password": mustEnv("CRIMSON_STAFF_PASSWORD", "Staff-Crimson-2026!")},
	}
}
