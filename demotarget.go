package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// demoHandler is a deliberately weak "clinic website" for demos and tests.
// It contains only fake data. The "fixed" switch lets a demo show the full cycle:
// scan -> request fix -> staff fixes -> rescan -> verified.
func demoHandler(fixed *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	page := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if fixed.Load() {
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "demo", HttpOnly: true})
		} else {
			w.Header().Set("Server", "Apache/2.4.29 (Ubuntu)")
			w.Header().Set("X-Powered-By", "PHP/7.2.1")
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "demo"})
		}
		fmt.Fprint(w, "<!doctype html><html><head><title>Sunrise Clinic (demo)</title></head><body><h1>Sunrise Clinic</h1><p>Book an appointment.</p></body></html>")
	}
	leak := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if fixed.Load() {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, body)
		}
	}
	mux.HandleFunc("/", page)
	mux.HandleFunc("/.env", leak("APP_ENV=production\nDB_HOST=10.0.0.5\nDB_PASSWORD=demo-not-a-real-password\nAPI_KEY=demo-not-a-real-key\n"))
	mux.HandleFunc("/.git/HEAD", leak("ref: refs/heads/main\n"))
	mux.HandleFunc("/backup.sql", leak("-- demo dump (fake data)\nCREATE TABLE patients (id INT, name TEXT);\nINSERT INTO patients VALUES (1,'Demo Patient');\n"))
	mux.HandleFunc("/phpinfo.php", leak("<h1>PHP Version 7.2.1</h1><p>phpinfo()</p>"))
	mux.HandleFunc("/phpmyadmin/", leak("<title>phpMyAdmin</title>"))
	mux.HandleFunc("/openapi.json", leak(`{"openapi":"3.0.0","info":{"title":"demo"}}`))
	return mux
}

// cmdDemoTarget runs the weak site plus fake listeners on medical/database ports (loopback only).
func cmdDemoTarget(args []string) {
	addr, portsCSV := "127.0.0.1:8081", "2575,11112,3306"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-addr":
			i++
			addr = args[i]
		case "-ports":
			i++
			portsCSV = args[i]
		}
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") && !strings.HasPrefix(addr, "localhost:") {
		fmt.Println("demo target only binds to loopback")
		return
	}
	var fixed atomic.Bool
	var mu sync.Mutex
	var lns []net.Listener
	var ports []string
	for _, p := range strings.Split(portsCSV, ",") {
		if p = strings.TrimSpace(p); p != "" {
			ports = append(ports, p)
		}
	}
	openPorts := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range ports {
			ln, err := net.Listen("tcp", "127.0.0.1:"+p)
			if err != nil {
				fmt.Printf("  (port %s unavailable, skipped)\n", p)
				continue
			}
			fmt.Printf("  fake service listening on 127.0.0.1:%s\n", p)
			lns = append(lns, ln)
			go func(ln net.Listener) {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					c.Close()
				}
			}(ln)
		}
	}
	closePorts := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, ln := range lns {
			ln.Close()
		}
		lns = nil
	}
	openPorts()
	// GET /_demo/fix flips the site into its "fixed" state (and /_demo/break back) for live demos.
	h := demoHandler(&fixed)
	mux := http.NewServeMux()
	mux.HandleFunc("/_demo/fix", func(w http.ResponseWriter, r *http.Request) {
		fixed.Store(true)
		closePorts()
		fmt.Fprintln(w, "site is now FIXED (ports closed)")
	})
	mux.HandleFunc("/_demo/break", func(w http.ResponseWriter, r *http.Request) {
		fixed.Store(false)
		closePorts()
		openPorts()
		fmt.Fprintln(w, "site is now VULNERABLE")
	})
	mux.Handle("/", h)
	fmt.Printf("Demo clinic site (intentionally weak, fake data) on http://%s\n", addr)
	fmt.Printf("  switch to fixed state:  curl http://%s/_demo/fix\n  back to weak state:     curl http://%s/_demo/break\n", addr, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Println(err)
	}
}
