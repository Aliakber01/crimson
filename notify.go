package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// loadDotEnv reads KEY=VALUE lines into the environment without overriding existing values.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
}

// notifyStaff pings the Crimson team on Telegram (kept from the prototype).
// Plain text on purpose: scan evidence can contain characters that break Markdown.
func notifyStaff(text string) {
	token, chat := os.Getenv("TELEGRAM_BOT_TOKEN"), os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chat == "" {
		return
	}
	c := &http.Client{Timeout: 8 * time.Second}
	resp, err := c.PostForm("https://api.telegram.org/bot"+token+"/sendMessage",
		url.Values{"chat_id": {chat}, "text": {text}})
	if err != nil {
		fmt.Println("[telegram] send failed")
		return
	}
	resp.Body.Close()
}

// explainWithClaude asks Claude for a tailored plain-language explanation of one finding.
// Evidence never contains secret values (see scanner), so it is safe to send.
func explainWithClaude(ctx context.Context, apiKey, model string, f *Finding, sector, lang string) (string, error) {
	t := f.I18n["en"]
	langName := "English"
	if lang == "az" {
		langName = "Azerbaijani"
	}
	prompt := fmt.Sprintf(`Finding from an automated security scan.
Organisation sector: %s
Severity: %s
Title: %s
Technical evidence: %s
Standard guidance: %s

Write for a non-technical manager at a small organisation, in %s:
1) What this means for their organisation in this sector, in 2-3 sentences, no jargon.
2) A short numbered list (max 4 steps) of what to do, ordered, concrete.
Do not invent facts beyond the evidence. Keep it under 150 words.`,
		sector, f.Severity, t.Title, f.Evidence, t.Fix, langName)

	body, _ := json.Marshal(map[string]any{
		"model": model, "max_tokens": 600,
		"system":   "You are a calm, precise security advisor for small organisations. You never exaggerate and never give offensive instructions.",
		"messages": []map[string]string{{"role": "user", "content": prompt}},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := (&http.Client{Timeout: 45 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("AI service returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("AI service returned no text")
	}
	return sb.String(), nil
}
