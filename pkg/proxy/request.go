package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
)

type Handler interface {
	Handle(Session) (*http.Response, error)
}

func Handle(handler Handler) HandlerFunc {
	return func(rctx Session) (*http.Response, error) {
		return handler.Handle(rctx)
	}
}

type HandlerFunc func(Session) (*http.Response, error)

func LogRequest(next HandlerFunc) HandlerFunc {
	return func(rctx Session) (*http.Response, error) {
		_ = rctx.Request.Write(os.Stdout)
		return next(rctx)
	}
}

func LogResponse(next HandlerFunc) HandlerFunc {
	return func(rctx Session) (*http.Response, error) {
		response, err := next(rctx)
		if err == nil {
			fmt.Printf("response [%s]\n", response.Status)
		}
		return response, nil
	}
}

func Forward() HandlerFunc {
	return func(rctx Session) (*http.Response, error) {

		upstreamConn, err := net.Dial("tcp", rctx.upstreamAddress())
		if err != nil {
			log.Printf("unable to connect to upstream host: %v", err)
			rctx.ClientConnection.Close()
			return nil, err
		}
		tlsUpstreamConfig := &tls.Config{
			ServerName: rctx.UpstreamHost,
		}
		tlsUpstreamConnection := tls.Client(upstreamConn, tlsUpstreamConfig)
		if err := tlsUpstreamConnection.Handshake(); err != nil {
			return nil, fmt.Errorf("unable to finish tls-handshake with upstream host: %v", err)
		}
		upstreamConn = tlsUpstreamConnection

		go func() {
			rctx.Request.Write(upstreamConn)
			if rctx.Request.Body != nil {
				io.Copy(upstreamConn, rctx.ClientConnection)
			}
		}()

		response, err := http.ReadResponse(bufio.NewReader(upstreamConn), rctx.Request)
		if err != nil {
			return nil, fmt.Errorf("unable to read response from upstream host: %v", err)
		}

		return response, nil
	}
}

func Blocked() HandlerFunc {
	return func(session Session) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     fmt.Sprintf("%d %s", http.StatusForbidden, "Blocked by Proxy"),
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Request:    session.Request,
		}, nil
	}
}

func StaticResponse(statusCode int, status string) HandlerFunc {
	return func(session Session) (*http.Response, error) {
		return &http.Response{
			StatusCode: statusCode,
			Status:     fmt.Sprintf("%d %s", statusCode, status),
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Request:    session.Request,
		}, nil
	}
}
