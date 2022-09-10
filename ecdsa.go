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
	"crypto/sha1"
	"crypto/sha256"
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
	if k.passwordDigest != nil {
		openFlags |= internal.NcryptSilentFlag
	}

	// Set the other flags
	// If a password is set for the key, set the flag NCRYPT_SILENT_FLAG, meaning
	// no UI should be shown to the user. Therefore, if the password is wrong,
	// the operation will fail silently.
	// Otherwise, if no password is set, do not set the flag, meaning a UI might
	// be shown to ask for it if the key needs one.
	if k.passwordDigest != nil {
		flags = internal.NcryptSilentFlag
	}

	// Try to get a handle to the key by its name
	_, err = internal.NCryptOpenKey(hProvider, &hKey, k.name, 0, openFlags)
	if err != nil {
		return nil, err
	}
	defer internal.NCryptFreeObject(hKey)

	// Set the key password / pin before signing if required.
	if k.passwordDigest != nil {
		_, err = internal.NCryptSetProperty(hKey, internal.NcryptPcpUsageauthProperty, k.passwordDigest, flags)
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
// If isUICompatible is set to false, and if a password is set, the user will only be
// able to authenticate to the key programmatically, by setting either of the
// NCRYPT_PIN_PROPERTY or the NCRYPT_PCP_USAGEAUTH_PROPERTY properties, but never
// via the Windows UI.
// If isUICompatible is set to true, and if a password is set, the user will only be
// able to authenticate to the key via the Windows UI or by setting the
// NCRYPT_PCP_USAGEAUTH_PROPERTY property, but never by setting the
// NCRYPT_PIN_PROPERTY property.
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
// The key usage can be set by combining the following flags using the OR operation :
//	- KeyUsageAllowDecrypt
//	- KeyUsageAllowSigning
// 	- KeyUsageAllowKeyAgreement
//	- KeyUsageAllowAllUsages
// If keyUsage is set to 0 instead, the default key usage will be used, which is
// SignOnly for ECDSA keys.
//
// TODO: Support UI Policies.
func GenerateECDSAKey(name string, password string, isUICompatible bool, curve elliptic.Curve, keyUsage uint32, overwrite bool) (Signer, error) {
	var hProvider uintptr
	var hKey uintptr
	var creationFlags uint32
	var flags uint32

	// Check that keyUsage contains a valid combination
	if keyUsage != 0 &&
		keyUsage != KeyUsageAllowAllUsages &&
		(keyUsage & ^(uint32(KeyUsageAllowDecrypt|KeyUsageAllowSigning|KeyUsageAllowKeyAgreement))) != 0 {
		return nil, fmt.Errorf("keyUsage parameter contains an unexpected combination of flags (%x)", keyUsage)
	}

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

	// If password is given, set it as NCRYPT_PCP_USAGE_AUTH_PROPERTY either :
	//	- after SHA-1 if UI compatibility is required
	//	- or after SHA-256 otherwise
	var passwordDigest []byte
	if len(password) != 0 {
		passwordBlob, err := internal.StringToUtf16Bytes(password)
		if err != nil {
			return nil, err
		}
		passwordBlob = passwordBlob[:len(passwordBlob)-2] // need to get rid of the last two 0x00 (L"\0")
		if isUICompatible {
			passwordBlobSha1 := sha1.Sum(passwordBlob)
			passwordDigest = passwordBlobSha1[:]
		} else {
			passwordBlobSha256 := sha256.Sum256(passwordBlob)
			passwordDigest = passwordBlobSha256[:]
		}
		_, err = internal.NCryptSetProperty(hKey, internal.NcryptPcpUsageauthProperty, passwordDigest, flags)
		if err != nil {
			return nil, err
		}
	} else {
		passwordDigest = nil
	}

	// Set the key type.
	if keyUsage != 0 {
		keyUsageBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(keyUsageBytes, keyUsage)
		_, err = internal.NCryptSetProperty(
			hKey,
			internal.NcryptKeyUsageProperty,
			keyUsageBytes,
			flags,
		)
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
			name:           name,
			passwordDigest: passwordDigest,
			pubKey:         publicKey,
			keyUsage:       keyUsage,
		},
	}, nil
}
