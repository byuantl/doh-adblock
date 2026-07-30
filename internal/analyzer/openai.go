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

type OpenAI struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

func NewOpenAI() *OpenAI {
	apiKey := os.Getenv("OPENAI_API_KEY")
	baseURL := os.Getenv("OPENAI_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAI{
		apiKey:  apiKey,
		model:   "gpt-4o",
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  http.DefaultClient,
	}
}

func (o *OpenAI) Name() string {
	return "openai"
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model    string           `json:"model"`
	Messages []openAIMessage  `json:"messages"`
	MaxTokens int             `json:"max_tokens,omitempty"`
}

type openAIChoice struct {
	Message openAIMessage `json:"message"`
}

type openAIResponse struct {
	Choices []openAIChoice `json:"choices"`
}

func (o *OpenAI) Analyze(ctx context.Context, domains []string) ([]Verdict, error) {
	prompt := fmt.Sprintf(`Given this list of domains queried by a web browser, flag any that are likely ad-tech, analytics, or tracking domains based on naming patterns, known company associations, or TLD conventions.

Return a JSON array of objects, each with fields: "domain" (string), "is_tracker" (bool), "confidence" (float 0-1), "reason" (string).

Domains:
%s`, strings.Join(domains, "\n"))

	body := openAIRequest{
		Model: o.model,
		Messages: []openAIMessage{
			{Role: "user", Content: prompt},
		},
		MaxTokens: 2000,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, fmt.Errorf("openai: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", &buf)
	if err != nil {
		return nil, fmt.Errorf("openai: create request: %w", err)
	}
	req.Header.Set("authorization", "Bearer "+o.apiKey)
	req.Header.Set("content-type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai: send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("openai: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	var apiResp openAIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("openai: decode response: %w", err)
	}
	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("openai: empty response")
	}

	text := apiResp.Choices[0].Message.Content
	text = extractJSON(text)

	var verdicts []Verdict
	if err := json.Unmarshal([]byte(text), &verdicts); err != nil {
		return nil, fmt.Errorf("openai: parse verdicts: %w\ntext: %s", err, text)
	}
	return verdicts, nil
}
