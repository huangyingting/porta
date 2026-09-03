package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/huangyingting/porta/internal/certutil"
)

func main() {
	certPath := flag.String("cert", "server.crt", "output certificate path (must not exist)")
	keyPath := flag.String("key", "server.key", "output private-key path (must not exist)")
	hosts := flag.String("hosts", "localhost,127.0.0.1", "comma-separated certificate DNS names and IP addresses")
	validFor := flag.Duration("valid-for", 30*24*time.Hour, "certificate validity")
	flag.Parse()

	if err := certutil.Generate(*certPath, *keyPath, certutil.Options{
		Hosts:    strings.Split(*hosts, ","),
		ValidFor: *validFor,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "porta-keygen:", err)
		os.Exit(1)
	}
	fmt.Printf("created %s and %s\n", *certPath, *keyPath)
}
