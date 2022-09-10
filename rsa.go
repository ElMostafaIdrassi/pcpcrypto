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
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"github.com/ElMostafaIdrassi/pcpcrypto/internal"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

// pcpRSAPrivateKey refers to a persistent RSA PCP private key.
// It completes the implementation of Signer by implementing its Sign()
// and Size() functions.
type pcpRSAPrivateKey struct {
	pcpPrivateKey
}

// Size returns the modulus size in bytes of the corresponding public key.
func (k *pcpRSAPrivateKey) Size() uint32 {
	return uint32((k.pubKey.(*rsa.PublicKey).N.BitLen() + 7) / 8)
}

// Sign is a required method of the crypto.Signer interface.
func (k *pcpRSAPrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	var hProvider uintptr
	var hKey uintptr
	var hash crypto.Hash
	var openFlags uint32
	var flags uint32

	// If opts is null or opts.HashFunc is 0, it means msg is not a digest and
	// must be signed directly. This is not recommended except for interoperability.
	// For the moment, we do not support signing arbitrary data (i.e. RSA Raw signature).
	if (opts == nil) || (opts.HashFunc() == 0) {
		return nil, fmt.Errorf("raw signature not supported")
	}
	hash = opts.HashFunc()

	// Get a handle to the PCP KSP.
	_, err = internal.NCryptOpenStorageProvider(&hProvider, internal.MsPlatformCryptoProvider, 0)
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

	// Try to get a handle to the key by its name.
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
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		return signPSS(k, hKey, msg, hash, pssOpts)
	}
	return signPKCS1v15(k, hKey, msg, hash)
}

// In order to sign with PSS, the flag NCRYPT_TPM_PAD_PSS_IGNORE_SALT must be set
// when calling NCryptSignHash, because otherwise, the signature fails with
// TPM_E_PCP_UNSUPPORTED_PSS_SALT, regardless of the cbSalt value set in BCRYPT_PSS_PADDING_INFO.
//
// The reason is related to how the TPM chip works :
//	- Pre-TPM Spec-1.16 TPM chips use a salt length equal to the maximum allowed salt size.
//	- Post-TPM Spec-1.16 TPM chips use a salt length equal to the hash length.
//
// Thus, we need to set the flag NCRYPT_TPM_PAD_PSS_IGNORE_SALT to tell the PCP KSP to ignore the
// passed salt length and default to the TPM's chip supported salt length.
//
// Also, when verifying the signature, pssOptions must have saltLength set to rsa.PSSSaltLengthAuto,
// so that the salt is detected using the 0x01 delimiter.
func signPSS(priv *pcpRSAPrivateKey, hKey uintptr, msg []byte, hash crypto.Hash, opts *rsa.PSSOptions) ([]byte, error) {

	var saltLength uint32
	var flags uint32
	var paddingInfo internal.BcryptPssPaddingInfo
	var sig []byte

	// opts.Hash, if not zero, overrides the passed hash function.
	if opts != nil && opts.Hash != 0 {
		hash = opts.Hash
	}

	// paddingInfo.cbSalt will be ignored by the PCP KSP, but we keep the parsing nevertheless :)
	switch opts.SaltLength {
	// PSSSaltLengthAuto causes the salt in a PSS signature to be as large
	// as possible when signing. We derive it from the key's length.
	// Pre-TPM Spec-1.16
	// See https://github.com/tpm2-software/tpm2-pkcs11/issues/417
	// See https://developer.mozilla.org/en-US/docs/Web/API/RsaPssParams
	case rsa.PSSSaltLengthAuto:
		saltLength = priv.Size() - 2 - uint32(hash.Size())
	// PSSSaltLengthEqualsHash causes the salt length to equal the length
	// of the hash used in the signature.
	// Post-TPM Spec-1.16
	case rsa.PSSSaltLengthEqualsHash:
		saltLength = uint32(hash.Size())
	default:
		saltLength = uint32(opts.SaltLength)
	}

	// Setup the PSS padding info.
	paddingInfo.CbSalt = saltLength
	switch hash {
	case crypto.SHA1:
		{
			paddingInfo.PszAlgId, _ = windows.UTF16FromString(internal.BcryptSha1Algorithm)
			break
		}
	case crypto.SHA256:
		{
			paddingInfo.PszAlgId, _ = windows.UTF16FromString(internal.BcryptSha256Algorithm)
			break
		}
	case crypto.SHA384:
		{
			paddingInfo.PszAlgId, _ = windows.UTF16FromString(internal.BcryptSha384Algorithm)
			break
		}
	case crypto.SHA512:
		{
			paddingInfo.PszAlgId, _ = windows.UTF16FromString(internal.BcryptSha512Algorithm)
			break
		}
	default:
		{
			return nil, fmt.Errorf("unsupported digest algo")
		}
	}

	// Set the other flags
	// If a password is set for the key, set the flag NCRYPT_SILENT_FLAG when signing,
	// meaning no UI should be shown to the user. Therefore, if the password is wrong,
	// the operation will fail silently.
	// Otherwise, if no password is set, do not set the flag, meaning if the key
	// needs a password, a UI might be shown to ask for it if the key needs one.
	flags = internal.BcryptPadPss | internal.NcryptTpmPadPssIgnoreSalt
	if priv.passwordDigest != nil {
		flags |= internal.NcryptSilentFlag
	}

	// Sign.
	sig, _, err := internal.NCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), msg, flags)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func signPKCS1v15(priv *pcpRSAPrivateKey, hKey uintptr, msg []byte, hash crypto.Hash) ([]byte, error) {

	var sig []byte
	var paddingInfo internal.BcryptPkcs1PaddingInfo
	var flags uint32

	// Setup the PKCS1v15 padding info.
	switch hash {
	case crypto.SHA1:
		{
			paddingInfo.PszAlgId, _ = windows.UTF16FromString(internal.BcryptSha1Algorithm)
			break
		}
	case crypto.SHA256:
		{
			paddingInfo.PszAlgId, _ = windows.UTF16FromString(internal.BcryptSha256Algorithm)
			break
		}
	case crypto.SHA384:
		{
			paddingInfo.PszAlgId, _ = windows.UTF16FromString(internal.BcryptSha384Algorithm)
			break
		}
	case crypto.SHA512:
		{
			paddingInfo.PszAlgId, _ = windows.UTF16FromString(internal.BcryptSha512Algorithm)
			break
		}
	default:
		{
			return nil, fmt.Errorf("unsupported digest algo")
		}
	}

	// Set the other flags
	// If a password is set for the key, set the flag NCRYPT_SILENT_FLAG when signing,
	// meaning no UI should be shown to the user. Therefore, if the password is wrong,
	// the operation will fail silently.
	// Otherwise, if no password is set, do not set the flag, meaning a UI might
	// be shown to ask for it if the key needs one.
	flags = internal.BcryptPadPkcs1
	if priv.passwordDigest != nil {
		flags |= internal.NcryptSilentFlag
	}

	// Sign.
	sig, _, err := internal.NCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), msg, flags)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// GenerateRSAKey generates a new signing RSA PCP Key with the specified name and bit
// length, then returns its corresponding pcpRSAPrivateKey instance.
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
// Supported RSA bit lengths are dictated by the TPM chip (usually 1024 and 2048)
// and by the PCP KSP. Therefore, there is no restriction on bitLength by GenerateRSAKey.
//
// At the time of writing, and even if we set the NCRYPT_MACHINE_KEY_FLAG flag during
// creation, the PCP KSP creates a key that applies to the Current User.
// Therefore, GenerateRSAKey will always generate keys that apply for the Current User.
//
// The key usage can be set by combining the following flags using the OR operation :
//	- KeyUsageAllowDecrypt
//	- KeyUsageAllowSigning
// 	- KeyUsageAllowKeyAgreement
//	- KeyUsageAllowAllUsages
// If keyUsage is set to 0 instead, the default key usage will be used, which is
// Sign + Decrypt for RSA keys.
//
// TODO: Support UI Policies.
func GenerateRSAKey(name string, password string, isUICompatible bool, bitLength uint32, keyUsage uint32, overwrite bool) (Signer, error) {
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

	// If name is empty, generate a unique random one
	if name == "" {
		uuidName, err := uuid.NewRandom()
		if err != nil {
			return nil, fmt.Errorf("uuid.NewRandom() failed: %v", err)
		}
		name = uuidName.String()
	}

	// Start the creation of the key
	_, err = internal.NCryptCreatePersistedKey(hProvider, &hKey, internal.BcryptRsaAlgorithm, name, 0, creationFlags)
	if err != nil {
		return nil, err
	}

	// Set the length of the key
	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, bitLength)
	_, err = internal.NCryptSetProperty(hKey, internal.NcryptLengthProperty, lengthBytes, flags)
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

	//	Read key's public part
	pubkeyBytes, _, err := internal.NCryptExportKey(hKey, 0, internal.BcryptRsapublicBlob, nil, flags)
	if err != nil {
		return nil, err
	}

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

	// Return *pcpRSAPrivateKey instance
	return &pcpRSAPrivateKey{
		pcpPrivateKey{
			name:           name,
			passwordDigest: passwordDigest,
			pubKey:         publicKey,
			keyUsage:       keyUsage,
		},
	}, nil
}
