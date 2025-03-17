package proxy

import (
	"net"
	"net/http"
)

type Session struct {
	UpstreamHost     string
	UpstreamPort     string
	ClientConnection net.Conn
	Request          *http.Request
}

func (session *Session) upstreamAddress() string {
	return session.UpstreamHost + ":" + session.UpstreamPort
}

func (session *Session) MatchHost(pattern string) bool {
	return match(pattern, session.UpstreamHost)
}
