package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/miekg/dns"

	"doh-adblock/internal/analyzer"
	"doh-adblock/internal/blocklist"
	"doh-adblock/internal/cache"
	"doh-adblock/internal/stats"
)

func writeDNSResponse(w http.ResponseWriter, resp *dns.Msg) {
	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

func buildBlockedResponse(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Authoritative = true
	if len(query.Question) > 0 && query.Question[0].Qtype == dns.TypeA {
		rr, _ := dns.NewRR(query.Question[0].Name + " 300 IN A 0.0.0.0")
		resp.Answer = append(resp.Answer, rr)
	}
	return resp
}

func dohHandler(w http.ResponseWriter, r *http.Request, bl *blocklist.Blocklist, c *cache.Cache, s *stats.Stats, ul *analyzer.UnblockedLog) {
	s.RecordQuery()

	if r.Method != http.MethodPost {
		http.Error(w, "only POST supported", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var query dns.Msg
	if err := query.Unpack(body); err != nil {
		http.Error(w, "invalid DNS message", http.StatusBadRequest)
		return
	}

	if len(query.Question) > 0 {
		q := query.Question[0]

		if cached, ok := c.Get(q); ok {
			s.RecordCacheHit()
			reply := cached.Copy()
			reply.Id = query.Id
			writeDNSResponse(w, reply)
			return
		}

		if bl.IsBlocked(q.Name) {
			s.RecordBlocked(q.Name)
			resp := buildBlockedResponse(&query)
			writeDNSResponse(w, resp)
			return
		}
	}

	resp, err := forwardToUpstream(&query)
	if err != nil {
		http.Error(w, "upstream failure", http.StatusBadGateway)
		return
	}

	if len(query.Question) > 0 {
		c.Set(query.Question[0], resp)
		ul.Record(query.Question[0].Name)
	}

	writeDNSResponse(w, resp)
}

func cacheCleanup(c *cache.Cache) {
	for {
		time.Sleep(5 * time.Minute)
		c.Cleanup()
	}
}

func forwardToUpstream(query *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	resp, _, err := c.Exchange(query, "1.1.1.1:53")
	return resp, err
}

func main() {
	bl, err := blocklist.Load("blocklist.txt")
	if err != nil {
		log.Fatalf("failed to load blocklist: %v", err)
	}

	c := cache.New()
	go cacheCleanup(c)

	s := stats.New()
	ul := analyzer.NewUnblockedLog(1000)

	http.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		dohHandler(w, r, bl, c, s, ul)
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		snap := s.Snapshot()
		top := ul.Top(10)
		snap.TopUnblocked = make([]stats.UnblockedEntry, len(top))
		for i, e := range top {
			snap.TopUnblocked[i] = stats.UnblockedEntry{Domain: e.Domain, Count: e.Count}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap)
	})

	fs := http.FileServer(http.Dir("web"))
	http.Handle("/dashboard/", http.StripPrefix("/dashboard/", fs))

	log.Println("DoH server listening on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "certs/cert.pem", "certs/key.pem", nil))
}
