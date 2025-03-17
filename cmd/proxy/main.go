package main

import (
	"bytes"
	"fmt"
	"github.com/mwildt/go-mitm/pkg/proxy"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {

	certsPath := "./certs"
	err := os.MkdirAll(certsPath, os.ModePerm)
	if err != nil {
		fmt.Printf("Fehler beim Erstellen des Verzeichnisses: %v\n", err)
		return
	}

	server, err := proxy.NewServer(func(session proxy.Session) (*http.Response, error) {

		if strings.HasPrefix(session.UpstreamHost, "demo.local.host") {

			handler := proxy.LogRequest(proxy.LogResponse(proxy.StaticResponse(
				&http.Response{
					StatusCode: http.StatusOK,
					Status:     fmt.Sprintf("%d %s", http.StatusOK, "Response from Server"),
					Proto:      "HTTP/1.1",
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header: http.Header{
						"x-proxy-version": []string{"v.0.0.0"},
					},
					Body:    io.NopCloser(bytes.NewReader(nil)),
					Request: session.Request,
				})))
			return handler(session)

		} else {
			handler := proxy.LogRequest(proxy.LogResponse(proxy.Forward()))
			return handler(session)
		}
	})

	if err != nil {
		log.Fatalf("err %v", err)
	}
	log.Fatalf("err %v", server.Listen(":8888"))
}
