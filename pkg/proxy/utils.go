package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func wildcardToRegex(pattern string) string {
	pattern = strings.ReplaceAll(pattern, ".", "\\.")
	pattern = strings.ReplaceAll(pattern, "*", "([^\\.]+)")
	return "^" + pattern + "$"
}

func match(pattern, hostname string) bool {
	if strings.HasPrefix(pattern, "*.") {
		rootDomain := strings.TrimPrefix(pattern, "*.")
		if hostname == rootDomain {
			return true
		}
	}

	regexPattern := wildcardToRegex(pattern)
	re := regexp.MustCompile(regexPattern)
	return re.MatchString(hostname)
}

func targetHostPort(request *http.Request) (string, string, error) {
	connectHost := request.Host
	if !strings.Contains(connectHost, "://") {
		connectHost = "none://" + connectHost
	}

	if parsedUrl, err := url.Parse(connectHost); err != nil {
		return "", "", fmt.Errorf("fehler beim parsen host: %v", err)
	} else {
		port := parsedUrl.Port()
		if port == "" {
			if parsedUrl.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		return parsedUrl.Hostname(), port, nil
	}
}
