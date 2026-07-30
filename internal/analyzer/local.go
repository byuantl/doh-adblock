package analyzer

import (
	"context"
	"strings"
)

type Local struct{}

func NewLocal() *Local {
	return &Local{}
}

func (l *Local) Name() string {
	return "local"
}

var trackerKeywords = []string{
	"adserver", "adsystem", "adtracker", "adtech",
	"doubleclick", "googlesyndication", "googleadservices",
	"scorecardresearch", "quantserve", "comscore",
	"outbrain", "taboola", "criteo",
	"rubiconproject", "openx", "pubmatic",
	"exelator", "bluekai", "rlcdn",
	"adsafeprotected", "moatads", "casalemedia",
	"appnexus", "spotxchange", "sharethrough",
	"analytics", "tracker", "tracking", "pixel",
	"beacon", "metrics", "insight",
}

var trackerSuffixes = []string{
	"ads.com", "ads.net", "adserver.com",
	"analytics.com", "analytics.net",
	"tracking.com", "tracker.com",
	"pixel.com", "pixel.net",
	"metrics.com", "metrics.net",
}

func domainHasTrackerKeyword(domain string) (string, bool) {
	dl := strings.ToLower(domain)
	for _, kw := range trackerKeywords {
		if strings.Contains(dl, kw) {
			return "contains known tracker keyword: " + kw, true
		}
	}
	for _, suf := range trackerSuffixes {
		if strings.HasSuffix(dl, suf) || strings.HasSuffix(dl, "."+suf) {
			return "domain matches known tracker pattern", true
		}
	}
	return "", false
}

var commonServices = map[string]bool{
	"google.com": true, "gmail.com": true, "youtube.com": true,
	"github.com": true, "stackoverflow.com": true,
	"microsoft.com": true, "apple.com": true, "amazon.com": true,
	"reddit.com": true, "twitter.com": true, "x.com": true,
	"facebook.com": true, "instagram.com": true,
	"netflix.com": true, "spotify.com": true,
	"cloudflare.com": true, "fastly.com": true,
	"akamai.net": true, "akamaiedge.net": true,
	"googlevideo.com": true, "ytimg.com": true,
	"githubusercontent.com": true,
}

func isKnownService(domain string) bool {
	dl := strings.ToLower(domain)
	return commonServices[dl]
}

func (l *Local) Analyze(ctx context.Context, domains []string) ([]Verdict, error) {
	verdicts := make([]Verdict, 0, len(domains))
	for _, d := range domains {
		v := Verdict{Domain: d}
		if isKnownService(d) {
			v.IsTracker = false
			v.Confidence = 1.0
			v.Reason = "known non-tracker service"
		} else if reason, ok := domainHasTrackerKeyword(d); ok {
			v.IsTracker = true
			v.Confidence = 0.8
			v.Reason = reason
		} else {
			continue
		}
		verdicts = append(verdicts, v)
	}
	return verdicts, nil
}
