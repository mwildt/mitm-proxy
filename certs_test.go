package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"strings"
	"testing"
)

func TestCertificateManager_wtf(t *testing.T) {

	connectHost := "ab.chatgpt.com:443"
	if !strings.Contains(connectHost, "://") {
		connectHost = "none://" + connectHost
	}

	u, e := url.Parse(connectHost)
	if e != nil {
		t.Errorf(e.Error())
	}
	t.Fatalf("u <%s> --%v-- p--%s--", u.Hostname(), u, u.Port())

}

func TestCertificateManager(t *testing.T) {

	cm := &CertificateManager{}
	if err := cm.init(); err != nil {
		t.Errorf(err.Error())
	}

	cert, err := cm.CreateServerCertificate("wolke.ohrenpirat.de")
	if err != nil {
		log.Fatal(fmt.Errorf("failed to create GetHostCertificate: %v", err))
	}

	if _, err := tls.Listen("tcp4", ":8888", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}); err != nil {
		log.Fatal(fmt.Errorf("failed to create tcp listener: %v", err))
	}

}
