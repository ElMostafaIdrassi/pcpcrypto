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
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/ElMostafaIdrassi/goncrypt"
	"github.com/ElMostafaIdrassi/pcpcrypto"
)

func main() {

	var data string
	var password string
	var seal bool
	var output string

	flag.StringVar(&data, "data", "", "Data to seal / unseal in hex format")
	flag.StringVar(&password, "password", "", "Password to use during sealing / unsealing")
	flag.BoolVar(&seal, "seal", false, "Seal data if true, unseal data if false")
	flag.Parse()

	if data == "" || password == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -data <data in hex format> -password <password> [-seal]\n", os.Args[0])
		return
	}

	err := pcpcrypto.Initialize(goncrypt.NewDefaultLogger(goncrypt.LogLevelNone))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcpcrypto.Initialize() failed: %v\n", err)
		return
	}
	defer pcpcrypto.Finalize()

	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hex.DecodeString(data) failed: %v\n", err)
		return
	}

	if seal {
		outputBytes, err := pcpcrypto.SealDataWithTPM(dataBytes, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pcpcrypto.SealDataWithTPM() failed: %v\n", err)
			return
		}

		output = hex.EncodeToString(outputBytes)
		fmt.Fprintf(os.Stdout, "Sealed Data: %s\n", output)
	} else {
		outputBytes, err := pcpcrypto.UnsealDataWithTPM(dataBytes, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pcpcrypto.UnsealDataWithTPM() failed: %v\n", err)
			return
		}

		output = hex.EncodeToString(outputBytes)
		fmt.Fprintf(os.Stdout, "Unsealed Data: %s\n", output)
	}
}
