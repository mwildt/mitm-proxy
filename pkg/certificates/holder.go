package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"path"
	"time"
)

type CaCertificateHolder struct {
	cert            *tls.Certificate
	certPEM, keyPEM []byte
}

func (holder *CaCertificateHolder) Write(datadir string, name string) error {
	err := writeFile(
		path.Join(datadir, fmt.Sprintf("%s.crt", name)),
		holder.certPEM)
	if err != nil {
		return err
	}
	return writeFile(
		path.Join(datadir, fmt.Sprintf("%s.key", name)),
		holder.keyPEM)
}

func (holder *CaCertificateHolder) Key() any {
	return holder.cert.PrivateKey
}

func (holder *CaCertificateHolder) Certificate() *x509.Certificate {
	return holder.cert.Leaf
}

func (holder *CaCertificateHolder) CreateServerCertificateForHostname(hostname string) (*tls.Certificate, error) {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{hostname},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal private key: %v", err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, holder.Certificate(), &privateKey.PublicKey, holder.Key())
	if err != nil {
		return nil, err
	}
	_, _, cert, err := tlsKeyPair(certBytes, privateKeyBytes)
	return cert, err
}
