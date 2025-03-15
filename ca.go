package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// Helper function to write PEM files
func writePemFile(filename string, blockType string, bytes []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})
}

// createKeyRootCA prüft, ob ein Zertifikat und ein privater Schlüssel existieren.
// Wenn nicht, werden sie erstellt und gespeichert.
func createKeyRootCA(path string, name string) (*tls.Certificate, error) {
	certFile := fmt.Sprintf("%s/%s.pem.crt", path, name)
	keyFile := fmt.Sprintf("%s/%s.pem.key", path, name)

	// Prüfe, ob Dateien vorhanden sind
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			// Zertifikat und Schlüssel existieren, laden und zurückgeben
			return loadKeyRootCA(certFile, keyFile)
		}
	}

	// Zertifikat und Schlüssel existieren nicht, neu generieren
	return generateAndSaveKeyRootCA(certFile, keyFile)
}

// loadKeyRootCA lädt ein Zertifikat und den zugehörigen Schlüssel.
func loadKeyRootCA(certFile, keyFile string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Lesen des Zertifikats: %v", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Lesen des Schlüssels: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Laden des Zertifikats/Schlüssels: %v", err)
	}
	return &cert, nil
}

// generateAndSaveKeyRootCA generiert ein selbstsigniertes Root-Zertifikat und speichert es.
func generateAndSaveKeyRootCA(certFile, keyFile string) (*tls.Certificate, error) {
	// Generiere privaten Schlüssel (ECDSA)
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Generieren des Schlüssels: %v", err)
	}

	// Zertifikatdaten
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My CA"},
			Country:      []string{"DE"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Erstelle selbstsigniertes Zertifikat
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Erstellen des Zertifikats: %v", err)
	}

	// Zertifikat speichern
	certOut, err := os.Create(certFile)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Erstellen der Zertifikatdatei: %v", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, fmt.Errorf("Fehler beim Schreiben des Zertifikats: %v", err)
	}

	// Privaten Schlüssel speichern
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Erstellen der Schlüsseldatei: %v", err)
	}
	defer keyOut.Close()
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Serialisieren des privaten Schlüssels: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, fmt.Errorf("Fehler beim Schreiben des Schlüssels: %v", err)
	}

	// Zertifikat und Schlüssel laden und zurückgeben
	return loadKeyRootCA(certFile, keyFile)
}

// createServerCertificate erstellt ein Zertifikat für einen spezifischen Host und gibt ein tls.Certificate zurück.
func createServerCertificate(rootCert *x509.Certificate, rootKey *crypto.PrivateKey, host string) (*tls.Certificate, error) {
	// Generiere einen neuen privaten Schlüssel für das Server-Zertifikat
	//privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Generieren des privaten Schlüssels: %v", err)
	}

	// Server-Zertifikat Template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"My Server"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Gültigkeit: 1 Jahr
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host}, // Füge den Hostnamen als SAN hinzu
	}

	// Signiere das Server-Zertifikat mit der Root-CA
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCert, &privateKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Erstellen des Server-Zertifikats: %v", err)
	}

	// Serialisiere den privaten Schlüssel
	keyBytes := x509.MarshalPKCS1PublicKey(nil)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Serialisieren des privaten Schlüssels: %v", err)
	}

	// Codierung in PEM-Format (für tls.Certificate)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	// Erstelle ein tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Erstellen des tls.Certificate: %v", err)
	}

	return &tlsCert, nil
}
