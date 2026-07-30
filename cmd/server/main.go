package main

import (
	"io"
	"log"
	"net/http"

	"github.com/miekg/dns"
)

func dohHandler(w http.ResponseWriter, r *http.Request) {
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

	resp, err := forwardToUpstream(&query)
	if err != nil {
		http.Error(w, "upstream failure", http.StatusBadGateway)
		return
	}

	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

func forwardToUpstream(query *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	resp, _, err := c.Exchange(query, "1.1.1.1:53")
	return resp, err
}

func main() {
	http.HandleFunc("/dns-query", dohHandler)
	log.Println("DoH server listening on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "certs/cert.pem", "certs/key.pem", nil))
}
