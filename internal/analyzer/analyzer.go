package analyzer

import "context"

type Verdict struct {
	Domain     string  `json:"domain"`
	IsTracker  bool    `json:"is_tracker"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

type Backend interface {
	Analyze(ctx context.Context, domains []string) ([]Verdict, error)
	Name() string
}
