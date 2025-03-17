package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"time"
)

func writeFile(path string, bytes []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0644); err != nil {
		return fmt.Errorf("Fehler beim Erstellen der Verzeichnisse: %v", err)
	} else {
		return os.WriteFile(path, bytes, 0644)
	}
}

func pemEncode(dataIn []byte, blocktype string) ([]byte, error) {
	var certBytes bytes.Buffer
	if err := pem.Encode(&certBytes, &pem.Block{Type: blocktype, Bytes: dataIn}); err != nil {
		return []byte{}, fmt.Errorf("Fehler beim Schreiben des Zertifikats: %v", err)
	}
	return certBytes.Bytes(), nil
}

func tlsKeyPair(certBytes, keyBytes []byte) (certPEM []byte, keyPEM []byte, cert *tls.Certificate, err error) {
	if certPEM, err := pemEncode(certBytes, "CERTIFICATE"); err != nil {
		return nil, nil, nil, fmt.Errorf("Fehler beim Codieren des Zertifikats: %v", err)
	} else if keyPEM, err := pemEncode(keyBytes, "EC PRIVATE KEY"); err != nil {
		return nil, nil, nil, fmt.Errorf("Fehler beim Codieren des privaten Schlüssels: %v", err)
	} else if cert, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, nil, nil, fmt.Errorf("Fehler beim Erstellen des KeyPairs: %v", err)
	} else {
		return certPEM, keyPEM, &cert, nil
	}
}

func loadCaCertificate(datadir, name string) (caCert CaCertificateHolder, found bool, err error) {
	certFile := path.Join(datadir, fmt.Sprintf("%s.crt", name))
	keyFile := path.Join(datadir, fmt.Sprintf("%s.key", name))
	if _, err := os.Stat(certFile); err != nil {
		return caCert, false, nil
	} else if _, err := os.Stat(keyFile); err != nil {
		return caCert, true, fmt.Errorf("Fehler beim Lesen des CA-Cert: Schlüssel fehlt: %v", err)
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return caCert, true, fmt.Errorf("Fehler beim Lesen des Zertifikats: %v", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return caCert, true, fmt.Errorf("Fehler beim Lesen des Schlüssels: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return caCert, true, fmt.Errorf("Fehler beim Laden des Zertifikats/Schlüssels: %v", err)
	}
	return CaCertificateHolder{&cert, certPEM, keyPEM}, true, nil
}

func createCACertificate() (caCert CaCertificateHolder, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return caCert, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return caCert, fmt.Errorf("Fehler beim Serialisieren des privaten Schlüssels: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MITM CA Root"},
			Country:      []string{"DE"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return CaCertificateHolder{}, fmt.Errorf("Fehler beim Erstellen des Root Zertifikats: %v", err)
	}
	caCert.certPEM, caCert.keyPEM, caCert.cert, err = tlsKeyPair(certBytes, keyBytes)
	if err != nil {
		return CaCertificateHolder{}, fmt.Errorf("Fehler beim Codieren der Daten: %v", err)
	}
	return caCert, nil
}
