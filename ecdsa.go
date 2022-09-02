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
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/ElMostafaIdrassi/pcpcrypto/internal"
	"github.com/google/uuid"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// pcpPrivateKey refers to a persistent ECDSA PCP private key.
// It completes the implementation of Signer by implementing its Sign() and
// Size() functions.
type pcpECDSAPrivateKey struct {
	pcpPrivateKey
}

// Size returns the curve field size in bytes.
func (k *pcpECDSAPrivateKey) Size() uint32 {
	return uint32((k.pubKey.(*ecdsa.PublicKey).Curve.Params().BitSize + 7) / 8)
}

// Sign is a required method of the crypto.Signer interface
func (k *pcpECDSAPrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {

	var hProvider uintptr
	var hKey uintptr
	var openFlags uint32
	var flags uint32
	var b cryptobyte.Builder
	var sig []byte

	// If opts is null or opts.HashFunc is 0, it means msg is not a digest and
	// must be signed directly. This is not recommended except for interoperability.
	// For the moment, we do not support signing arbitrary data (i.e. ECDSA Raw signature).
	if (opts == nil) || (opts.HashFunc() == 0) {
		return nil, fmt.Errorf("raw signature not supported")
	}

	// Get a handle to the PCP KSP
	_, err := internal.NCryptOpenStorageProvider(&hProvider, internal.MsPlatformCryptoProvider, 0)
	if err != nil {
		return nil, err
	}
	defer internal.NCryptFreeObject(hProvider)

	// Set the opening flags
	if len(k.password) != 0 {
		openFlags |= internal.NcryptSilentFlag
	}

	// Set the other flags
	// If a password is set for the key, set the flag NCRYPT_SILENT_FLAG, meaning
	// no UI should be shown to the user. Therefore, if the password is wrong,
	// the operation will fail silently.
	// Otherwise, if no password is set, do not set the flag, meaning a UI might
	// be shown to ask for it if the key needs one.
	if len(k.password) != 0 {
		flags = internal.NcryptSilentFlag
	}

	// Try to get a handle to the key by its name
	_, err = internal.NCryptOpenKey(hProvider, &hKey, k.name, 0, openFlags)
	if err != nil {
		return nil, err
	}
	defer internal.NCryptFreeObject(hKey)

	// Set the key password / pin before signing if required.
	if len(k.password) != 0 {
		passwordBlob, err := internal.StringToUtf16Bytes(k.password)
		if err != nil {
			return nil, err
		}
		_, err = internal.NCryptSetProperty(hKey, internal.NcryptPinProperty, passwordBlob, flags)
		if err != nil {
			return nil, err
		}
	}

	// Sign
	sig, _, err = internal.NCryptSignHash(hKey, nil, msg, flags)
	if err != nil {
		return nil, err
	}

	// The EDCSA signature returned by the PCP KSP is in RAW format (r,s).
	// Therefore, we need to ASN.1 encode it before returning it.
	rInt := big.NewInt(0)
	rInt.SetBytes(sig[:len(sig)/2])
	sInt := big.NewInt(0)
	sInt.SetBytes(sig[len(sig)/2:])
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(rInt)
		b.AddASN1BigInt(sInt)
	})
	sig, err = b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("asn.1 encoding failed: %v", err)
	}
	return sig, nil
}

// GenerateECDSAKey generates a new signing ECDSA PCP Key with the specified name and
// curve, then returns its corresponding pcpECDSAPrivateKey instance.
//
// If name is empty, it will generate a unique random name beforehand.
//
// If password is empty, it will generate the key with no password / pin, making it
// usable with no authentication.
//
// If overwrite is set, and if a key with the same name already exists, it will
// be overwritten.
//
// Supported EC curves are dictated by the (usually at least NIST-P256) and by the PCP KSP.
// GenerateECDSAKey only supports NIST-P256/P384/P521 which are the only curves supported
// by the PCP KSP (at the time of writing).
//
// At the time of writing, and even if we set the NCRYPT_MACHINE_KEY_FLAG flag during
// creation, the PCP KSP creates a key that applies to the Current User.
// Therefore, GenerateECDSAKey will always generate keys that apply for the Current User.
//
// The key usage is left to be the default one for ECDSA, which is Sign.
// TODO: Support UI Policies + manually set key usages.
func GenerateECDSAKey(name string, password string, curve elliptic.Curve, overwrite bool) (Signer, error) {
	var hProvider uintptr
	var hKey uintptr
	var creationFlags uint32
	var flags uint32

	// Get a handle to the PCP KSP
	_, err := internal.NCryptOpenStorageProvider(&hProvider, internal.MsPlatformCryptoProvider, 0)
	if err != nil {
		return nil, err
	}
	defer internal.NCryptFreeObject(hProvider)

	// Set the creation flags
	if overwrite {
		creationFlags |= internal.NcryptOverwriteKeyFlag
	}

	// Set the other flags
	if len(password) != 0 {
		flags |= internal.NcryptSilentFlag
	}

	// Check the specified curve
	curveName := ""
	switch curve {
	case elliptic.P256():
		curveName = internal.BcryptEcdsaP256Algorithm
	case elliptic.P384():
		curveName = internal.BcryptEcdsaP384Algorithm
	case elliptic.P521():
		curveName = internal.BcryptEcdsaP521Algorithm
	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	// If name is empty, generate a unique random one
	if name == "" {
		uuidName, err := uuid.NewRandom()
		if err != nil {
			return nil, fmt.Errorf("uuid.NewRandom() failed: %v", err)
		}
		name = uuidName.String()
	}

	// Start the creation of the key
	_, err = internal.NCryptCreatePersistedKey(hProvider, &hKey, curveName, name, 0, creationFlags)
	if err != nil {
		return nil, err
	}

	// If password is given, set it as NCRYPT_PIN_PROPERTY
	if len(password) != 0 {
		passwordBlob, err := internal.StringToUtf16Bytes(password)
		if err != nil {
			return nil, err
		}
		_, err = internal.NCryptSetProperty(hKey, internal.NcryptPinProperty, passwordBlob, flags)
		if err != nil {
			return nil, err
		}
	}

	// Finalize (create) the key
	_, err = internal.NCryptFinalizeKey(hKey, flags)
	if err != nil {
		return nil, err
	}
	defer internal.NCryptFreeObject(hKey)

	// Read key's public part
	pubkeyBytes, _, err := internal.NCryptExportKey(hKey, 0, internal.BcryptEccpublicBlob, nil, flags)
	if err != nil {
		return nil, err
	}

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

	// Return *pcpECDSAPrivateKey instance
	return &pcpECDSAPrivateKey{
		pcpPrivateKey{
			name:     name,
			password: password,
			pubKey:   publicKey,
		},
	}, nil
}
