// Copyright (c) 2020, El Mostafa IDRASSI.
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

package pcpcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Signer implements crypto.Signer and additional functions (i.e. Name()).
// This allows a pcpPrivateKey to be usable whenever a crypto.Signer
// is expected, in addition to allowing the caller to perform additional
// actions on it that are not typically allowed / implemented by the
// crypto.Signer interface (i.e Name()).
type Signer interface {
	crypto.Signer

	// Name returns the PCP Key name.
	Name() string

	// Size returns the PCP public key size.
	Size() int

	// Delete deletes the PCP Key from the PCP KSP.
	Delete() error
}

// pcpPrivateKey refers to a persistent private key present in the PCP KSP.
// It must have a name and might or might not be protected with a password.
// pcpPrivateKey partially implements Signer by only implementing
// its Public(), Name() and Delete() functions.
// pcpRSAPrivateKey and pcpECDSAPrivateKey each implement the remaining
// Sign() and Size() functions.
type pcpPrivateKey struct {
	name     string           // name is the PCP Key name.
	password string           // password is the PCP Key password / pin.
	pubKey   crypto.PublicKey // pubKey is the public part of the PCP Key.
}

// Public is a required method of the crypto.Signer interface.
func (k pcpPrivateKey) Public() crypto.PublicKey {
	return k.pubKey
}

// Name returns the PCP Key name.
func (k pcpPrivateKey) Name() string {
	return k.name
}

// Delete deletes the PCP Key from the PCP KSP.
func (k pcpPrivateKey) Delete() error {
	var hProvider uintptr
	var hKey uintptr

	// Get a handle to the PCP KSP
	err := NCryptOpenStorageProvider(&hProvider, pcpProviderName, 0)
	if err != nil {
		return fmt.Errorf("NCryptOpenStorageProvider() failed: %v", err)
	}
	defer NCryptFreeObject(hProvider)

	// Try to get a handle to the key by its name
	err = NCryptOpenKey(hProvider, &hKey, k.name, 0, NcryptSilentFlag)
	if err != nil {
		return fmt.Errorf("NCryptOpenKey() failed: %v", err)
	}
	defer NCryptFreeObject(hKey)

	// Try to delete the key
	// Surprisingly, this does not require the PCP Key password ?
	err = NCryptDeleteKey(hKey, 0) // Will display a UI if necessary, but why ?
	if err != nil {
		return fmt.Errorf("NCryptDeleteKey() failed: %v", err)
	}

	return nil
}

// findPcpKey tries to open a handle to an existing PCP key by its name
// and read its public part before creating and returning either a pcpRSAPrivateKey or
// a pcpECDSAPrivateKey. If the PCP key does not exist, it returns nil.
// If password is set, it will be saved in the private key and used
// before each signature, requiring no interaction from the user.
// Otherwise, if no password is set, a UI prompt will show up during the signature
// asking for the password only if the key needs one.
// After all operations are done on the resulting key, its handle should be freed by calling
// the Close() function on the key.
// N.B :
// In the case where the key was created using NCRYPT_UI_POLICY, entering
// the correct password in the UI prompt will succeed. However, if the key was created
// using NCRYPT_PIN_PROPERTY instead of a NCRYPT_UI_POLICY, entering the correct
// password in the UI prompt will always fail. This is a bug in the PCP KSP,
// as it cannot handle normal password in the UI prompt.
func findKey(name string, password string) (Signer, error) {
	var hProvider uintptr
	var hKey uintptr
	var publicKey crypto.PublicKey

	// Get a handle to the PCP KSP
	err := NCryptOpenStorageProvider(&hProvider, pcpProviderName, 0)
	if err != nil {
		return nil, fmt.Errorf("NCryptOpenStorageProvider() failed: %v", err)
	}
	defer NCryptFreeObject(hProvider)

	// Try to get a handle to the key by its name
	err = NCryptOpenKey(hProvider, &hKey, name, 0, NcryptSilentFlag)
	if err != nil {
		return nil, fmt.Errorf("NCryptOpenKey() failed: %v", err)
	}
	defer NCryptFreeObject(hKey)

	// Read key's public part
	pubkeyBytes, isRSA, err := getNCryptBufferPublicKey(hKey)
	if err != nil {
		return nil, fmt.Errorf("getNCryptBufferPublicKey() failed: %v", err)
	}

	if isRSA {

		// Construct rsa.PublicKey from BCRYPT_RSAPUBLIC_BLOB
		eSize := binary.LittleEndian.Uint32(pubkeyBytes[8:12])
		nSize := binary.LittleEndian.Uint32(pubkeyBytes[12:16])

		eBytes := pubkeyBytes[24 : 24+eSize]
		nBytes := pubkeyBytes[24+eSize : 24+eSize+nSize]

		eInt := big.NewInt(0)
		eInt.SetBytes(eBytes)
		nInt := big.NewInt(0)
		nInt.SetBytes(nBytes)

		publicKey = &rsa.PublicKey{N: nInt, E: int(eInt.Int64())}

		return &pcpRSAPrivateKey{
			pcpPrivateKey{
				name:     name,
				password: password,
				pubKey:   publicKey,
			},
		}, nil
	} else {

		// Construct ecdsa.PublicKey from BCRYPT_ECCPUBLIC_BLOB
		var keyByteSize int
		var keyCurve elliptic.Curve

		magic := binary.LittleEndian.Uint32(pubkeyBytes[0:4])
		if magic == bcryptEcdsaPublicP256Magic {
			keyByteSize = 32
			keyCurve = elliptic.P256()
		} else if magic == bcryptEcdsaPublicP384Magic {
			keyByteSize = 48
			keyCurve = elliptic.P384()
		} else if magic == bcryptEcdsaPublicP521Magic {
			keyByteSize = 66
			keyCurve = elliptic.P521()
		} else {
			return nil, fmt.Errorf("Unexpected ECC magic number %.8X", magic)
		}

		xBytes := pubkeyBytes[8 : 8+keyByteSize]
		yBytes := pubkeyBytes[8+keyByteSize : 8+keyByteSize+keyByteSize]

		xInt := big.NewInt(0)
		xInt.SetBytes(xBytes)
		yInt := big.NewInt(0)
		yInt.SetBytes(yBytes)

		publicKey = &ecdsa.PublicKey{Curve: keyCurve, X: xInt, Y: yInt}

		return &pcpECDSAPrivateKey{
			pcpPrivateKey{
				name:     name,
				password: password,
				pubKey:   publicKey,
			},
		}, nil
	}
}
