package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	// Beispiel: Zertifikat und Schlüssel erstellen/laden
	certsPath := "./certs"
	err := os.MkdirAll(certsPath, os.ModePerm)
	if err != nil {
		fmt.Printf("Fehler beim Erstellen des Verzeichnisses: %v\n", err)
		return
	}

	proxy, err := NewProxy()
	if err != nil {
		log.Fatalf("err %v", err)
	}
	log.Fatalf("err %v", proxy.Listen(":8888"))
}
