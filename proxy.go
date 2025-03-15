package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Proxy struct {
	certificateManager *CertificateManager
	logger             *log.Logger
}

func NewProxy() (*Proxy, error) {
	cm, err := NewCertificateManager()
	if err != nil {
		return nil, err
	}
	return &Proxy{
		certificateManager: cm,
		logger:             log.New(os.Stdout, "[Proxy] ", log.LstdFlags|log.Lmsgprefix),
	}, nil
}

func (proxy *Proxy) Listen(laddr string) error {
	addr, err := net.ResolveTCPAddr("tcp", laddr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	proxy.logger.Printf("listen for incoming connections on %s", laddr)
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("err %v", err)
			continue
		}
		go proxy.handleConnection(connection)
	}

}

func (proxy *Proxy) handleConnection(connection net.Conn) {
	proxy.logger.Printf("handle incoming connection from %s", connection.RemoteAddr().String())
	defer connection.Close()

	var data []byte
	teeReader := io.TeeReader(
		bufio.NewReader(connection),
		bufio.NewWriter(bytes.NewBuffer(data)))

	request, err := http.ReadRequest(bufio.NewReader(teeReader))

	if err != nil {
		proxy.logger.Printf("Fehler beim Parsen des Request // err: %v", err)
		if len(data) > 0 {
			proxy.logger.Printf("Fehler beim Parsen des Request // msg: %s", string(data))
		}
		return
	}

	if request.Method == "CONNECT" {
		if err = proxy.handleConnect(connection, request); err != nil {
			proxy.logger.Printf("got error from HTTPS handler %v", err)
			return
		}
	} else {
		if err = proxy.handleHttp(connection, request); err != nil {
			proxy.logger.Printf("got error from HTTP handler %v", err)
			return
		}
	}
}

func getTargetHost(request *http.Request) (string, error) {
	connectHost := request.Host
	if !strings.Contains(connectHost, "://") {
		connectHost = "none://" + connectHost
	}

	if parsedUrl, err := url.Parse(connectHost); err != nil {
		return "", fmt.Errorf("fehler beim parsen host: %v", err)
	} else {
		return parsedUrl.Hostname(), nil
	}
}

func (proxy *Proxy) handleConnect(clientConn net.Conn, request *http.Request) error {
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return fmt.Errorf("Fehler beim Senden der Bestätigung: %v", err)
	}
	targetHost, err := getTargetHost(request)
	cert, err := proxy.certificateManager.CreateServerCertificate(targetHost)
	if err != nil {
		return fmt.Errorf("unable o create server-certificate: %v", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*cert}}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS-Handshake mit Client fehlgeschlagen: %v", err)
	}

	if targetHost == "demo.local.host" {
		// die verbindung wird unterbrochen
		req, err := http.ReadRequest(bufio.NewReader(tlsConn))
		if err != nil {
			return fmt.Errorf("unable to parse reqeust in tunnel // err: %v", err)
		}
		proxy.logger.Println("got request in tunnel")
		req.Write(os.Stdout)

		res := &http.Response{
			StatusCode: http.StatusOK,
			Status:     fmt.Sprintf("%d %s", http.StatusOK, "Response from Proxy"),
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"x-proxy-version": []string{"v.0.0.0"},
			},
			Body:    io.NopCloser(bytes.NewReader(nil)),
			Request: req,
		}
		proxy.logger.Println("Write Response")
		res.Write(tlsConn)
		return nil
	} else {
		// die verbinudng wird in der tat weitergereicht
		upstreamConn, err := net.Dial("tcp", request.Host)
		if err != nil {
			log.Printf("unable to connect to upstream host: %v", err)
			tlsConn.Close()
			return err
		}

		tlsUpstreamConfig := &tls.Config{InsecureSkipVerify: true}
		tlsUpstreamConn := tls.Client(upstreamConn, tlsUpstreamConfig)
		if err := tlsUpstreamConn.Handshake(); err != nil {
			return fmt.Errorf("unable to finish tls-handshake with upstream host: %v", err)
		}

		go io.Copy(tlsUpstreamConn, io.TeeReader(tlsConn, log.New(os.Stdout, "[Proxy.https.request] ", log.LstdFlags|log.Lmsgprefix).Writer()))
		io.Copy(tlsConn, io.TeeReader(tlsUpstreamConn, log.New(os.Stdout, "[Proxy.https.response] ", log.LstdFlags|log.Lmsgprefix).Writer()))

		return nil
	}

}

func (proxy *Proxy) handleHttp(clientConn net.Conn, request *http.Request) error {
	proxy.logger.Printf("handleHttp : %v\n", request)
	request.RequestURI = ""
	if !strings.HasPrefix(request.URL.Scheme, "http") {
		request.URL.Scheme = "http" // Standard auf HTTP setzen
	}
	if request.URL.Host == "" {
		request.URL.Host = request.Host
	}
	// 3. Weiterleiten an den Zielserver
	resp, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		proxy.logger.Printf("Fehler beim Weiterleiten: %v\n", err)
		resp := &http.Response{
			Status:     "502 Bad Gateway",     // HTTP-Status
			StatusCode: http.StatusBadGateway, // HTTP Statuscode 200
			Header:     make(http.Header),     // Header initialisieren
		}
		resp.Write(clientConn)
		return err
	}
	defer resp.Body.Close()
	resp.Write(clientConn)
	return nil
}
