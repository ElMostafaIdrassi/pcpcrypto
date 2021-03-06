// Copyright (c) 2020-2021, El Mostafa IDRASSI.
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
	"unsafe"

	"golang.org/x/sys/windows"
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

	// IsLocalMachine returns true if the key resides in the Local Machine
	// store instead of the Current User.
	IsLocalMachine() bool

	// Size returns the PCP public key size.
	Size() uint32

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
	name         string           // name is the PCP Key name.
	password     string           // password is the PCP Key password / pin.
	localMachine bool             // localMachine determines whether the key resides in the Current User or Local Machine store.
	pubKey       crypto.PublicKey // pubKey is the public part of the PCP Key.
}

// Public is a required method of the crypto.Signer interface.
func (k pcpPrivateKey) Public() crypto.PublicKey {
	return k.pubKey
}

// Name returns the PCP Key name.
func (k pcpPrivateKey) Name() string {
	return k.name
}

// IsLocalMachine returns true if the key resides in the Local Machine
// store instead of the Current User.
func (k pcpPrivateKey) IsLocalMachine() bool {
	return k.localMachine
}

// Delete deletes the PCP Key from the PCP KSP.
func (k pcpPrivateKey) Delete() error {
	var hProvider uintptr
	var hKey uintptr
	var flags uint32

	// Get a handle to the PCP KSP
	_, err := nCryptOpenStorageProvider(&hProvider, msPlatformCryptoProvider, 0)
	if err != nil {
		return err
	}
	defer nCryptFreeObject(hProvider)

	// Set the flags
	flags = ncryptSilentFlag
	if k.localMachine {
		flags |= ncryptMachineKeyFlag
	}

	// Try to get a handle to the key by its name
	_, err = nCryptOpenKey(hProvider, &hKey, k.name, 0, flags)
	if err != nil {
		return err
	}
	defer nCryptFreeObject(hKey)

	// Try to delete the key
	_, err = nCryptDeleteKey(hKey, 0)
	if err != nil {
		return err
	}

	return nil
}

// FindKey tries to open a handle to an existing PCP key by its name
// and read its public part before creating and returning either a pcpRSAPrivateKey or
// a pcpECDSAPrivateKey. If the PCP key does not exist, it returns nil.
// If password is set, it will be saved in the private key and used
// before each signature, requiring no interaction from the user.
// Otherwise, if no password is set, a UI prompt might show up during the signature
// asking for the password if the key needs one.
// If localMachine is set to true, the search will be perfomed in the Local Machine
// key store. Otherwise, it will be performed in the Current User key store.
// After all operations are done on the resulting key, its handle should be freed by calling
// the Close() function on the key.
// N.B :
// In the case where the key was created using NCRYPT_UI_POLICY, entering
// the correct password in the UI prompt will succeed. However, if the key was created
// using NCRYPT_PIN_PROPERTY instead of a NCRYPT_UI_POLICY, entering the correct
// password in the UI prompt will always fail. This is a bug in the PCP KSP,
// as it cannot handle normal password in the UI prompt.
func FindKey(name string, password string, localMachine bool) (Signer, error) {
	var hProvider uintptr
	var hKey uintptr
	var flags uint32
	var publicKey crypto.PublicKey

	// Get a handle to the PCP KSP
	_, err := nCryptOpenStorageProvider(&hProvider, msPlatformCryptoProvider, 0)
	if err != nil {
		return nil, err
	}
	defer nCryptFreeObject(hProvider)

	// Set the flags
	flags = ncryptSilentFlag
	if localMachine {
		flags |= ncryptMachineKeyFlag
	}

	// Try to get a handle to the key by its name
	_, err = nCryptOpenKey(hProvider, &hKey, name, 0, flags)
	if err != nil {
		return nil, err
	}
	defer nCryptFreeObject(hKey)

	// Get key's algorithm
	alg, _, err := getNCryptBufferProperty(hKey, ncryptAlgorithmGroupProperty, ncryptSilentFlag)
	if err != nil {
		return nil, err
	}
	algStr, err := utf16BytesToString(alg)
	if err != nil {
		return nil, err
	}

	// Read key's public part
	var pubkeyBytes []byte
	var isRSA bool
	if algStr == ncryptRsaAlgorithm {
		pubkeyBytes, _, err = getNCryptKeyBlob(hKey, bcryptRsapublicBlob, ncryptSilentFlag)
		isRSA = true
	} else if algStr == ncryptEcdsaAlgorithm {
		pubkeyBytes, _, err = getNCryptKeyBlob(hKey, bcryptEccpublicBlob, ncryptSilentFlag)
	} else {
		return nil, fmt.Errorf("unsupported algo: only RSA and ECDSA keys are supported")
	}
	if err != nil {
		return nil, err
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
				name:         name,
				password:     password,
				localMachine: localMachine,
				pubKey:       publicKey,
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
			return nil, fmt.Errorf("unexpected ECC magic number %.8X", magic)
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
				name:         name,
				password:     password,
				localMachine: localMachine,
				pubKey:       publicKey,
			},
		}, nil
	}
}

// GetKeys tries to retrieve all existing PCP keys.
// If localMachine is set to true, it will retrieve the keys that
// are in the Local Machine key store. Otherwise, it will retrieve
// the keys that are in the Current User key store.
func GetKeys(localMachine bool) ([]pcpPrivateKey, error) {
	var hProvider uintptr
	var pState unsafe.Pointer
	var pKeyName *nCryptKeyName
	var flags uint32
	var ret uint32
	var err error

	keys := make([]pcpPrivateKey, 0)

	// Open a handle to the "Microsoft Platform Crypto Provider" provider.
	_, err = nCryptOpenStorageProvider(
		&hProvider,
		msPlatformCryptoProvider,
		0,
	)
	if err != nil {
		return nil, err
	}
	defer nCryptFreeObject(hProvider)

	// Set the flags
	flags = ncryptSilentFlag
	if localMachine {
		flags |= ncryptMachineKeyFlag
	}

	// Retrieve 1 key item at a time.
	for {
		ret, err = nCryptEnumKeys(
			hProvider,
			"",
			&pKeyName,
			&pState,
			flags,
		)
		if err != nil {
			if ret == 0x8009002A { // NTE_NO_MORE_ITEMS
				break
			} else {
				return nil, err
			}
		} else {
			keyName := windows.UTF16PtrToString(pKeyName.pszName)

			var hKey uintptr
			var pubkeyBytes []byte
			var isRSA bool

			// Open a handle to the key
			_, err = nCryptOpenKey(hProvider, &hKey, keyName, 0, flags)
			if err != nil {
				return nil, err
			}
			defer nCryptFreeObject(hKey)

			// Get key's algorithm
			alg, _, err := getNCryptBufferProperty(hKey, ncryptAlgorithmGroupProperty, ncryptSilentFlag)
			if err != nil {
				return nil, err
			}
			algStr, err := utf16BytesToString(alg)
			if err != nil {
				return nil, err
			}

			// Read key's public part
			if algStr == ncryptRsaAlgorithm {
				pubkeyBytes, _, err = getNCryptKeyBlob(hKey, bcryptRsapublicBlob, ncryptSilentFlag)
				isRSA = true
			} else if algStr == ncryptEcdsaAlgorithm {
				pubkeyBytes, _, err = getNCryptKeyBlob(hKey, bcryptEccpublicBlob, ncryptSilentFlag)
			} else {
				continue
			}
			if err != nil {
				return nil, err
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

				publicKey := &rsa.PublicKey{N: nInt, E: int(eInt.Int64())}

				keys = append(keys, pcpPrivateKey{
					name:         keyName,
					password:     "",
					localMachine: localMachine,
					pubKey:       publicKey,
				})
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
					return nil, fmt.Errorf("unexpected ECC magic number %.8X", magic)
				}

				xBytes := pubkeyBytes[8 : 8+keyByteSize]
				yBytes := pubkeyBytes[8+keyByteSize : 8+keyByteSize+keyByteSize]

				xInt := big.NewInt(0)
				xInt.SetBytes(xBytes)
				yInt := big.NewInt(0)
				yInt.SetBytes(yBytes)

				publicKey := &ecdsa.PublicKey{Curve: keyCurve, X: xInt, Y: yInt}

				keys = append(keys, pcpPrivateKey{
					name:         keyName,
					password:     "",
					localMachine: localMachine,
					pubKey:       publicKey,
				})
			}
		}
	}
	nCryptFreeBuffer(pState)
	nCryptFreeBuffer(unsafe.Pointer(pKeyName))

	return keys, nil
}
