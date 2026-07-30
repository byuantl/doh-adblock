package blocklist

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

type Blocklist struct {
	mu      sync.RWMutex
	domains map[string]struct{}
}

func Load(path string) (*Blocklist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bl := &Blocklist{domains: make(map[string]struct{})}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		domain := strings.ToLower(fields[1])
		bl.domains[domain] = struct{}{}
	}
	return bl, scanner.Err()
}

func (bl *Blocklist) IsBlocked(domain string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	_, blocked := bl.domains[domain]
	return blocked
}
