package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type Anthropic struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

func NewAnthropic() *Anthropic {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	return &Anthropic{
		apiKey:  apiKey,
		model:   "claude-sonnet-4-20250514",
		baseURL: "https://api.anthropic.com/v1",
		client:  http.DefaultClient,
	}
}

func (a *Anthropic) Name() string {
	return "anthropic"
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	Messages  []anthropicMessage `json:"messages"`
	MaxTokens int                `json:"max_tokens"`
}

type anthropicContent struct {
	Text string `json:"text"`
}

type anthropicResponse struct {
	Content []anthropicContent `json:"content"`
}

func (a *Anthropic) Analyze(ctx context.Context, domains []string) ([]Verdict, error) {
	prompt := fmt.Sprintf(`Given this list of domains queried by a web browser, flag any that are likely ad-tech, analytics, or tracking domains based on naming patterns, known company associations, or TLD conventions.

Return a JSON array of objects, each with fields: "domain" (string), "is_tracker" (bool), "confidence" (float 0-1), "reason" (string).

Domains:
%s`, strings.Join(domains, "\n"))

	body := anthropicRequest{
		Model: a.model,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
		MaxTokens: 2000,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, fmt.Errorf("anthropic: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/messages", &buf)
	if err != nil {
		return nil, fmt.Errorf("anthropic: create request: %w", err)
	}
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic: send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	var apiResp anthropicResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("anthropic: decode response: %w", err)
	}
	if len(apiResp.Content) == 0 {
		return nil, fmt.Errorf("anthropic: empty response")
	}

	text := apiResp.Content[0].Text
	text = extractJSON(text)

	var verdicts []Verdict
	if err := json.Unmarshal([]byte(text), &verdicts); err != nil {
		return nil, fmt.Errorf("anthropic: parse verdicts: %w\ntext: %s", err, text)
	}
	return verdicts, nil
}

func extractJSON(s string) string {
	start := strings.Index(s, "[")
	if start == -1 {
		return s
	}
	end := strings.LastIndex(s, "]")
	if end == -1 || end < start {
		return s
	}
	return s[start : end+1]
}
