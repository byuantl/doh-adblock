package analyzer

import (
	"sort"
	"sync"
)

type UnblockedEntry struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

type UnblockedLog struct {
	mu      sync.Mutex
	domains map[string]int64
	maxSize int
}

func NewUnblockedLog(maxSize int) *UnblockedLog {
	return &UnblockedLog{domains: make(map[string]int64), maxSize: maxSize}
}

func (l *UnblockedLog) Record(domain string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.domains[domain]++
	if len(l.domains) > l.maxSize {
		l.evict()
	}
}

func (l *UnblockedLog) evict() {
	entries := make([]struct {
		domain string
		count  int64
	}, 0, len(l.domains))
	for d, c := range l.domains {
		entries = append(entries, struct {
			domain string
			count  int64
		}{d, c})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count < entries[j].count
	})
	remove := len(entries) - l.maxSize
	for i := 0; i < remove; i++ {
		delete(l.domains, entries[i].domain)
	}
}

func (l *UnblockedLog) Top(n int) []UnblockedEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := make([]UnblockedEntry, 0, len(l.domains))
	for d, c := range l.domains {
		entries = append(entries, UnblockedEntry{Domain: d, Count: c})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}
