package cache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	msg     *dns.Msg
	expires time.Time
}

type Cache struct {
	mu    sync.RWMutex
	items map[string]entry
}

func New() *Cache {
	return &Cache{items: make(map[string]entry)}
}

func key(q dns.Question) string {
	return q.Name + "|" + dns.TypeToString[q.Qtype]
}

func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.items[key(q)]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.msg, true
}

func (c *Cache) Set(q dns.Question, msg *dns.Msg) {
	if len(msg.Answer) == 0 {
		return
	}
	ttl := msg.Answer[0].Header().Ttl
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key(q)] = entry{
		msg:     msg,
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (c *Cache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, e := range c.items {
		if now.After(e.expires) {
			delete(c.items, k)
		}
	}
}
