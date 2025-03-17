package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/mwildt/go-mitm/pkg/certificates"
	"io"
	"log"
	"net"
	"net/http"
	"os"
)

type Server struct {
	handler            HandlerFunc
	certificateManager *certificates.Manager
	logger             *log.Logger
}

func NewServer(handler HandlerFunc) (*Server, error) {
	cm, err := certificates.NewCertificateManager()
	if err != nil {
		return nil, err
	}
	return &Server{
		handler:            handler,
		certificateManager: cm,
		logger:             log.New(os.Stdout, "[Server] ", log.LstdFlags|log.Lmsgprefix),
	}, nil
}

func (proxy *Server) Listen(listenAddress string) error {
	addr, err := net.ResolveTCPAddr("tcp", listenAddress)
	if err != nil {
		return err
	}
	return proxy.ListenTCP(addr)
}

func (proxy *Server) ListenTCP(listenAddress *net.TCPAddr) error {
	listener, err := net.ListenTCP("tcp", listenAddress)
	if err != nil {
		return err
	}
	defer func(listener *net.TCPListener) {
		err := listener.Close()
		if err != nil {
			proxy.logger.Printf("err %v", err)
		}
	}(listener)
	proxy.logger.Printf("listen for incoming connections on %s", listenAddress.String())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting incoming connections on %s: %s", listenAddress.String(), err.Error())
			continue
		}
		go proxy.acceptConnection(connection)
	}
}

func (proxy *Server) acceptConnection(connection net.Conn) {
	proxy.logger.Printf("handle incoming connection from %s", connection.RemoteAddr().String())
	defer func(connection net.Conn) {
		err := connection.Close()
		if err != nil {
			proxy.logger.Printf("err %v", err)
		}
	}(connection)

	var data []byte
	teeReader := io.TeeReader(
		bufio.NewReader(connection),
		bufio.NewWriter(bytes.NewBuffer(data)))

	request, err := http.ReadRequest(bufio.NewReader(teeReader))

	if err != nil {
		proxy.logger.Printf("Error reading Request from %s: %s", connection.RemoteAddr().String(), err.Error())
		if len(data) > 0 {
			proxy.logger.Printf("Error reading Request body from %s: %s", connection.RemoteAddr().String(), err.Error())
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

func (proxy *Server) handleRequest(context Session) error {
	proxy.logger.Printf("handle Request from %s to %s via %s",
		context.ClientConnection.RemoteAddr().String(),
		context.Request.URL,
		context.upstreamAddress(),
	)

	response, err := proxy.handler(context)

	if err != nil {
		return err
	}
	proxy.logger.Printf("send response [%s] to client %s", response.Status, context.ClientConnection.RemoteAddr().String())
	err = response.Write(context.ClientConnection)
	if err != nil {
		return err
	}
	return nil
}

func (proxy *Server) handleConnect(clientConn net.Conn, connectRequest *http.Request) error {
	proxy.logger.Printf("handle connect Request from %s", clientConn.RemoteAddr().String())
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return fmt.Errorf("Fehler beim Senden der Bestätigung: %v", err)
	}
	targetHost, targetPort, err := targetHostPort(connectRequest)
	if err != nil {
		return fmt.Errorf("unable to determin target host from connect Request: %v", err)
	}

	cert, err := proxy.certificateManager.CreateServerCertificate(targetHost)
	if err != nil {
		return fmt.Errorf("unable o create server-certificate: %v", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*cert}}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS-Handshake mit Client fehlgeschlagen: %v", err)
	}

	request, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		return fmt.Errorf("unable to parse reqeust in tunnel // err: %v", err)
	}

	return proxy.handleRequest(Session{targetHost, targetPort, tlsConn, request})

}

func (proxy *Server) handleHttp(clientConn net.Conn, request *http.Request) error {
	proxy.logger.Printf("handle http Request from %s: %s", clientConn.RemoteAddr().String(), request.RequestURI)
	targetHost, targetPort, err := targetHostPort(request)
	if err != nil {
		return fmt.Errorf("unable to determin target host from connect Request: %v", err)
	}
	return proxy.handleRequest(Session{targetHost, targetPort, clientConn, request})
}
