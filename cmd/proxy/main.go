package main

import (
	"fmt"
	"github.com/mwildt/go-mitm/pkg/proxy"
	"log"
	"net/http"
	"os"
)

func main() {

	certsPath := "./certs"
	err := os.MkdirAll(certsPath, os.ModePerm)
	if err != nil {
		fmt.Printf("Fehler beim Erstellen des Verzeichnisses: %v\n", err)
		return
	}

	coreHandler := func(session proxy.Session) proxy.HandlerFunc {
		if session.MatchHost("demo.local.host") {
			return proxy.StaticResponse(http.StatusOK, "OK from Proxy")
		} else if session.MatchHost("*.google.com") {
			return proxy.Blocked()
		} else {
			return proxy.Forward()
		}
	}

	handler := proxy.LogRequest(proxy.LogResponse(Wrap(coreHandler)))

	server, err := proxy.NewServer(handler)

	if err != nil {
		log.Fatalf("err %v", err)
	}
	log.Fatalf("err %v", server.Listen(":8888"))
}

func Wrap(handler func(session proxy.Session) proxy.HandlerFunc) proxy.HandlerFunc {
	return func(session proxy.Session) (*http.Response, error) {
		return handler(session)(session)
	}
}
