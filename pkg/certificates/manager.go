package certificates

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
)

type Manager struct {
	data, name string
	caCert     CaCertificateHolder

	logger *log.Logger

	mutex *sync.Mutex
	cache map[string]*tls.Certificate
}

func NewCertificateManager() (*Manager, error) {
	cm := &Manager{
		data:   "./certs",
		name:   "mitm_root_ca",
		mutex:  &sync.Mutex{},
		cache:  make(map[string]*tls.Certificate),
		logger: log.New(os.Stdout, "[Manager] ", log.LstdFlags|log.Lmsgprefix),
	}
	return cm, cm.init()
}

func (cm *Manager) init() error {
	cm.logger.Printf("initialize Manager")
	if caCert, loaded, err := loadCaCertificate(cm.data, cm.name); err != nil {
		cm.logger.Printf("fehler beim laden des root-ca-certificates")
		return err
	} else if loaded {
		cm.logger.Printf("root-ca-certificates erfolgreich geladen")
		cm.caCert = caCert
		return nil
	} else {
		cm.logger.Printf("root-ca-certificates nicht gefunden, erstelle neue Zertifikate")
		if caCert, err = createCACertificate(); err != nil {
			return err
		} else {
			cm.logger.Printf("root-ca-certificates erfolgreich erstellt")
			cm.caCert = caCert
			caCert.Write(cm.data, cm.name)
			return err
		}
	}
}

func (cm *Manager) CreateServerCertificate(hostname string) (*tls.Certificate, error) {
	if cert, exists := cm.cache[hostname]; exists {
		return cert, nil
	} else {
		cm.mutex.Lock()
		defer cm.mutex.Unlock()
		if caCert, err := cm.caCert.CreateServerCertificateForHostname(hostname); err != nil {
			return nil, err
		} else {
			cm.cache[hostname] = caCert
			cm.logger.Printf("createed new certificate for hostname %s", hostname)
			return caCert, err
		}
	}
}
