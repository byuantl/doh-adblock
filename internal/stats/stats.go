package stats

import (
	"sort"
	"sync"
	"sync/atomic"
)

type Stats struct {
	TotalQueries   int64
	BlockedQueries int64
	CacheHits      int64
	mu             sync.Mutex
	topBlocked     map[string]int64
}

func New() *Stats {
	return &Stats{topBlocked: make(map[string]int64)}
}

func (s *Stats) RecordQuery() {
	atomic.AddInt64(&s.TotalQueries, 1)
}

func (s *Stats) RecordBlocked(domain string) {
	atomic.AddInt64(&s.BlockedQueries, 1)
	s.mu.Lock()
	s.topBlocked[domain]++
	s.mu.Unlock()
}

func (s *Stats) RecordCacheHit() {
	atomic.AddInt64(&s.CacheHits, 1)
}

type Snapshot struct {
	TotalQueries   int64        `json:"total_queries"`
	BlockedQueries int64        `json:"blocked_queries"`
	CacheHits      int64        `json:"cache_hits"`
	TopBlocked     []BlockedDOM `json:"top_blocked,omitempty"`
}

type BlockedDOM struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	top := make([]BlockedDOM, 0, len(s.topBlocked))
	for d, c := range s.topBlocked {
		top = append(top, BlockedDOM{Domain: d, Count: c})
	}
	s.mu.Unlock()

	sort.Slice(top, func(i, j int) bool {
		return top[i].Count > top[j].Count
	})
	if len(top) > 10 {
		top = top[:10]
	}

	return Snapshot{
		TotalQueries:   atomic.LoadInt64(&s.TotalQueries),
		BlockedQueries: atomic.LoadInt64(&s.BlockedQueries),
		CacheHits:      atomic.LoadInt64(&s.CacheHits),
		TopBlocked:     top,
	}
}
