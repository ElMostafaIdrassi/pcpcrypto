// Copyright (c) 2020-2022, El Mostafa IDRASSI.
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
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/ElMostafaIdrassi/pcpcrypto/internal"
	"golang.org/x/sys/windows"
)

const (
	KeyUsageAllowDecrypt      = 0x00000001 // NcryptAllowDecryptFlag
	KeyUsageAllowSigning      = 0x00000002 // NcryptAllowSigningFlag
	KeyUsageAllowKeyAgreement = 0x00000004 // NcryptAllowKeyAgreementFlag
	KeyUsageAllowAllUsages    = 0x00ffffff // NcryptAllowAllUsages
)

// Signer implements crypto.Signer and additional functions (i.e. Name()).
//
// This allows a pcpPrivateKey to be usable whenever a crypto.Signer
// is expected, in addition to allowing the caller to perform additional
// actions on it that are not typically allowed / implemented by the
// crypto.Signer interface (i.e Name()).
type Signer interface {
	crypto.Signer

	// Name returns the PCP key name.
	Name() string

	// Size returns the PCP public key size.
	Size() uint32

	// KeyUsage returns the PCP key usage.
	KeyUsage() uint32

	// IsLocalMachine returns whether the key applies to the Local Machine or to the Current User.
	IsLocalMachine() bool

	// Delete deletes the PCP key.
	Delete() error
}

// pcpPrivateKey refers to a persistent PCP private key.
// It must have a name and might or might not be protected with a password / pin.
//
// pcpPrivateKey partially implements Signer by only implementing
// its Public(), Name() and Delete() functions.
//
// pcpRSAPrivateKey and pcpECDSAPrivateKey each implement the remaining
// Sign() and Size() functions.
type pcpPrivateKey struct {
	name           string           // name is the PCP key name.
	passwordDigest []byte           // passwordDigest is the PCP key password / pin digest (SHA-1 if UI compatible, SHA-256 otherwise)
	pubKey         crypto.PublicKey // pubKey is the public part of the PCP key.
	keyUsage       uint32           // keyUsage is the PCP key usage.
	isLocalMachine bool             // isLocalMachine determines whether the key applies to the Local Machine or to the Current User.
}

// Public is a required method of the crypto.Signer interface.
func (k pcpPrivateKey) Public() crypto.PublicKey {
	return k.pubKey
}

// Name returns the PCP key name.
func (k pcpPrivateKey) Name() string {
	return k.name
}

// KeyUsage returns the PCP key usage.
func (k pcpPrivateKey) KeyUsage() uint32 {
	return k.keyUsage
}

// IsLocalMachine returns whether the key applies to the Local Machine or to the Current User.
func (k pcpPrivateKey) IsLocalMachine() bool {
	return k.isLocalMachine
}

// Delete deletes the PCP key.
func (k pcpPrivateKey) Delete() error {
	var hProvider uintptr
	var hKey uintptr
	var flags uint32

	// Get a handle to the PCP KSP
	_, err := internal.NCryptOpenStorageProvider(&hProvider, internal.MsPlatformCryptoProvider, 0)
	if err != nil {
		return err
	}
	defer internal.NCryptFreeObject(hProvider)

	// Set the flags
	flags = internal.NcryptSilentFlag
	if k.isLocalMachine {
		flags |= internal.NcryptMachineKeyFlag
	}

	// Try to get a handle to the key by its name
	_, err = internal.NCryptOpenKey(hProvider, &hKey, k.name, 0, flags)
	if err != nil {
		return err
	}
	defer internal.NCryptFreeObject(hKey)

	// Try to delete the key
	_, err = internal.NCryptDeleteKey(hKey, 0)
	if err != nil {
		return err
	}

	return nil
}

// FindKey tries to open a handle to an existing PCP key by its name
// and read its public part before creating and returning either a
// pcpRSAPrivateKey or a pcpECDSAPrivateKey. If the PCP key does not exist,
// it returns nil.
//
// If password is set, it will be saved in the private key and used
// before each signature, requiring no interaction from the user.
// Otherwise, if no password is set, a UI prompt might show up during the
// signature asking for the password / pin if the key needs one.
//
// We differentiate between :
//	- PCP keys created with a password set in the Windows UI,
//	- PCP keys created with a password set programmatically using NCRYPT_PIN_PORPERTY.
// A password set via the UI prompt is transformed internally into its
// SHA-1 digest, while a password set programmatically via NCRYPT_PIN_PROPERTY is
// transformed internally into its SHA-256 digest.
// Therefore, if isUICompatible is set to true, we will store the SHA-1 of the password,
// while we will store its SHA-256 if isUICompatible is set to false.
//
// If isLocalMachine is set to true, the search will look for keys that apply to the
// Local Machine. Otherwise, it will look for keys that apply for the Current User.
//
// After all operations are done on the resulting key, its handle should be
// freed by calling the Close() function on the key.
func FindKey(name string, password string, isUICompatible bool, isLocalMachine bool) (Signer, error) {
	var hProvider uintptr
	var hKey uintptr
	var flags uint32
	var publicKey crypto.PublicKey
	var passwordDigest []byte

	// Get a handle to the PCP KSP
	_, err := internal.NCryptOpenStorageProvider(&hProvider, internal.MsPlatformCryptoProvider, 0)
	if err != nil {
		return nil, err
	}
	defer internal.NCryptFreeObject(hProvider)

	// Set the flags
	flags = internal.NcryptSilentFlag
	if isLocalMachine {
		flags |= internal.NcryptMachineKeyFlag
	}

	// Try to get a handle to the key by its name
	_, err = internal.NCryptOpenKey(hProvider, &hKey, name, 0, flags)
	if err != nil {
		return nil, err
	}
	defer internal.NCryptFreeObject(hKey)

	// Get key's algorithm
	algBytes, _, err := internal.NCryptGetProperty(hKey, internal.NcryptAlgorithmGroupProperty, internal.NcryptSilentFlag)
	if err != nil {
		return nil, err
	}
	alg, err := internal.Utf16BytesToString(algBytes)
	if err != nil {
		return nil, err
	}

	// Get key's usage
	usageBytes, _, err := internal.NCryptGetProperty(hKey, internal.NcryptKeyUsageProperty, internal.NcryptSilentFlag)
	if err != nil {
		return nil, err
	}
	if len(usageBytes) != 4 {
		return nil, fmt.Errorf("nCryptGetProperty() returned unexpcted output: expected 4 bytes, got %v bytes", len(usageBytes))
	}
	usage := binary.LittleEndian.Uint32(usageBytes)

	// Get the password digest.
	if password != "" {
		passwordBlob, err := internal.StringToUtf16Bytes(password)
		if err != nil {
			return nil, err
		}
		passwordBlob = passwordBlob[:len(passwordBlob)-2] // need to get rid of the last two 0x00 (L"\0")
		if isUICompatible {
			passwordSha1Bytes := sha1.Sum(passwordBlob)
			passwordDigest = passwordSha1Bytes[:]
		} else {
			passwordSha256Bytes := sha256.Sum256(passwordBlob)
			passwordDigest = passwordSha256Bytes[:]
		}
	} else {
		passwordDigest = nil
	}

	// Read key's public part
	var pubkeyBytes []byte
	var isRSA bool
	if alg == internal.NcryptRsaAlgorithm {
		pubkeyBytes, _, err = internal.NCryptExportKey(hKey, 0, internal.BcryptRsapublicBlob, nil, 0)
		isRSA = true
	} else if alg == internal.NcryptEcdsaAlgorithm {
		pubkeyBytes, _, err = internal.NCryptExportKey(hKey, 0, internal.BcryptEccpublicBlob, nil, 0)
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
				name:           name,
				passwordDigest: passwordDigest,
				pubKey:         publicKey,
				keyUsage:       usage,
				isLocalMachine: isLocalMachine,
			},
		}, nil
	} else {

		// Construct ecdsa.PublicKey from BCRYPT_ECCPUBLIC_BLOB
		var keyByteSize int
		var keyCurve elliptic.Curve

		magic := binary.LittleEndian.Uint32(pubkeyBytes[0:4])
		if magic == internal.BcryptEcdsaPublicP256Magic {
			keyByteSize = 32
			keyCurve = elliptic.P256()
		} else if magic == internal.BcryptEcdsaPublicP384Magic {
			keyByteSize = 48
			keyCurve = elliptic.P384()
		} else if magic == internal.BcryptEcdsaPublicP521Magic {
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
				name:           name,
				passwordDigest: passwordDigest,
				pubKey:         publicKey,
				keyUsage:       usage,
				isLocalMachine: isLocalMachine,
			},
		}, nil
	}
}

// GetKeys tries to retrieve all existing PCP keys.
//
// If isLocalMachine is set to true, the search will retrieve the keys that apply to the
// Local Machine. Otherwise, it will retrieve the keys that apply for the Current User.
func GetKeys(isLocalMachine bool) ([]Signer, error) {
	var hProvider uintptr
	var pState unsafe.Pointer
	var pKeyName unsafe.Pointer
	var flags uint32
	var ret uint32
	var err error

	keys := make([]Signer, 0)

	// Open a handle to the "Microsoft Platform Crypto Provider" provider.
	_, err = internal.NCryptOpenStorageProvider(
		&hProvider,
		internal.MsPlatformCryptoProvider,
		0,
	)
	if err != nil {
		return nil, err
	}
	defer internal.NCryptFreeObject(hProvider)

	// Set the flags
	flags = internal.NcryptSilentFlag
	if isLocalMachine {
		flags |= internal.NcryptMachineKeyFlag
	}

	// Retrieve 1 key item at a time.
	for {
		ret, err = internal.NCryptEnumKeys(
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
			keyNameSt := unsafe.Slice((*internal.NcryptKeyName)(pKeyName), 1)
			if keyNameSt != nil || len(keyNameSt) != 1 {
				keyName := windows.UTF16PtrToString(keyNameSt[0].PszName)

				var hKey uintptr
				var pubkeyBytes []byte
				var isRSA bool

				// Open a handle to the key
				_, err = internal.NCryptOpenKey(hProvider, &hKey, keyName, 0, flags)
				if err != nil {
					return nil, err
				}
				defer internal.NCryptFreeObject(hKey)

				// Get key's algorithm
				algBytes, _, err := internal.NCryptGetProperty(hKey, internal.NcryptAlgorithmGroupProperty, internal.NcryptSilentFlag)
				if err != nil {
					return nil, err
				}
				alg, err := internal.Utf16BytesToString(algBytes)
				if err != nil {
					return nil, err
				}

				// Get key's usage
				usageBytes, _, err := internal.NCryptGetProperty(hKey, internal.NcryptKeyUsageProperty, internal.NcryptSilentFlag)
				if err != nil {
					return nil, err
				}
				if len(usageBytes) != 4 {
					return nil, fmt.Errorf("nCryptGetProperty() returned unexpcted output: expected 4 bytes, got %v bytes", len(usageBytes))
				}
				keyUsage := binary.LittleEndian.Uint32(usageBytes)

				// Read key's public part
				if alg == internal.NcryptRsaAlgorithm {
					pubkeyBytes, _, err = internal.NCryptExportKey(hKey, 0, internal.BcryptRsapublicBlob, nil, 0)
					isRSA = true
				} else if alg == internal.NcryptEcdsaAlgorithm {
					pubkeyBytes, _, err = internal.NCryptExportKey(hKey, 0, internal.BcryptEccpublicBlob, nil, 0)
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

					keys = append(keys, &pcpRSAPrivateKey{
						pcpPrivateKey{
							name:           keyName,
							passwordDigest: nil,
							pubKey:         publicKey,
							keyUsage:       keyUsage,
							isLocalMachine: isLocalMachine,
						},
					})
				} else {

					// Construct ecdsa.PublicKey from BCRYPT_ECCPUBLIC_BLOB
					var keyByteSize int
					var keyCurve elliptic.Curve

					magic := binary.LittleEndian.Uint32(pubkeyBytes[0:4])
					if magic == internal.BcryptEcdsaPublicP256Magic {
						keyByteSize = 32
						keyCurve = elliptic.P256()
					} else if magic == internal.BcryptEcdsaPublicP384Magic {
						keyByteSize = 48
						keyCurve = elliptic.P384()
					} else if magic == internal.BcryptEcdsaPublicP521Magic {
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

					keys = append(keys, &pcpECDSAPrivateKey{
						pcpPrivateKey{
							name:           keyName,
							passwordDigest: nil,
							pubKey:         publicKey,
							keyUsage:       keyUsage,
							isLocalMachine: isLocalMachine,
						},
					})
				}
			}

		}
	}
	internal.NCryptFreeBuffer(pState)
	internal.NCryptFreeBuffer(unsafe.Pointer(pKeyName))

	return keys, nil
}
