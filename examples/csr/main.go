// Copyright (c) 2020-2023, El Mostafa IDRASSI.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ElMostafaIdrassi/goncrypt"
	"github.com/ElMostafaIdrassi/pcpcrypto"
)

func main() {
	logFilePath := "csr_example.log"
	logFile, err := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Log file creation failed: %v\n", err)
		os.Exit(1)
	}

	err = pcpcrypto.Initialize(goncrypt.NewDefaultFileLogger(goncrypt.LogLevelDebug, logFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcpcrypto.Initialize() failed: %v\n", err)
		return
	}
	defer pcpcrypto.Finalize()

	key, err := pcpcrypto.GenerateRSAKey("", "", false, false, 1024, 0, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcpcrypto.GenerateRSAKey() failed: %v\n", err)
		return
	}
	defer key.Delete()

	signatureAlgorithm := x509.SHA256WithRSA

	csrTemplate := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: key.Name()},
		SignatureAlgorithm: signatureAlgorithm,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "x509.CreateCertificateRequest() failed: %v\n", err)
		return
	}

	csrPEMBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}

	fmt.Fprintf(os.Stdout, "CSR\n%s\n", string(pem.EncodeToMemory(csrPEMBlock)))
}
