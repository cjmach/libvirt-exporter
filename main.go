/*
 * Copyright (C) 2022  Carlos Machado
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var CLI struct {
	ListenAddress      string   `short:"l" name:"listen-address" default:":8080" help:"The address to listen on for HTTP(S) requests."`
	MetricsPath        string   `short:"m" name:"metrics-path" default:"/metrics" help:"Path to the metrics endpoint."`
	ConnectionUri      string   `short:"u" name:"connection-uri" required:"" placeholder:"URI" help:"Libvirt connection URI."`
	ExportGuestMetrics bool     `short:"e" name:"export-guest-metrics" default:"false" help:"If present, export guest metrics. Requires root privileges and qemu-agent running inside the domain."`
	DomainNames        []string `short:"d" name:"domain-names" optional:"" placeholder:"NAME" help:"Export metrics for these domains only. By default, metrics from all domains are exported."`
	CertificateFile    string   `short:"c" name:"certificate-file" optional:"" placeholder:"FILE" help:"Path to the certificate file. The file must contain PEM encoded data. The certificate file may contain intermediate certificates following the leaf certificate to form a certificate chain."`
	KeyFile            string   `short:"k" name:"key-file" optional:"" placeholder:"FILE" help:"Path to the private key file. The file must contain PEM encoded data."`
}

func main() {
	kong.Parse(&CLI)

	exporter := NewExporter(CLI.ConnectionUri, CLI.ExportGuestMetrics, CLI.DomainNames)
	defer exporter.Close()

	log.Printf("[INFO] Connected to Libvirt URI %s\n", CLI.ConnectionUri)

	prometheus.MustRegister(exporter)
	log.Println("[INFO] Successfully registered exporter.")

	http.Handle(CLI.MetricsPath, promhttp.Handler())

	log.Printf("[INFO] Listening on %s\n", CLI.ListenAddress)
	log.Printf("[INFO] Serving metrics on endpoint %s\n", CLI.MetricsPath)

	if fileExists(CLI.CertificateFile) && fileExists(CLI.KeyFile) {
		keyPair, err := tls.LoadX509KeyPair(CLI.CertificateFile, CLI.KeyFile)
		if err != nil {
			log.Fatalf("[ERROR] Failed to load X509 key-pair: %s", err)
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{keyPair},
		}
		server := &http.Server{
			Addr:      CLI.ListenAddress,
			Handler:   nil,
			TLSConfig: config,
		}
		server.ListenAndServeTLS("", "")
	} else {
		server := &http.Server{
			Addr:    CLI.ListenAddress,
			Handler: nil,
		}
		server.ListenAndServe()
	}

}

// fileExists returns true if file 'f' exists on the filesystem.
func fileExists(f string) bool {
	_, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}
