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
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

// pcpRSAPrivateKey refers to a persistent RSA private key in the PCP KSP.
// It completes the implementation of Signer by implementing its Sign()
// and Size() functions.
type pcpRSAPrivateKey struct {
	pcpPrivateKey
}

// Size returns the modulus size in bytes of the corresponding public key.
func (k *pcpRSAPrivateKey) Size() int {
	return (k.pubKey.(*rsa.PublicKey).N.BitLen() + 7) / 8
}

// Sign is a required method of the crypto.Signer interface.
func (k *pcpRSAPrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	var hProvider uintptr
	var hKey uintptr
	var hash crypto.Hash

	// If opts is null or opts.HashFunc is 0, it means msg is not a digest and
	// must be signed directly. This is not recommended except for interoperability.
	// For the moment, we do not support signing arbitrary data (i.e. RSA Raw signature).
	if (opts == nil) || (opts.HashFunc() == 0) {
		return nil, fmt.Errorf("Raw signature not supported")
	}
	hash = opts.HashFunc()

	// Get a handle to the PCP KSP.
	err = nCryptOpenStorageProvider(&hProvider, pcpProviderName, 0)
	if err != nil {
		return nil, fmt.Errorf("NCryptOpenStorageProvider() failed: %v", err)
	}
	defer nCryptFreeObject(hProvider)

	// Try to get a handle to the key by its name.
	err = nCryptOpenKey(hProvider, &hKey, k.name, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("NCryptOpenKey() failed: %v", err)
	}
	defer nCryptFreeObject(hKey)

	// Set the key password / pin before signing if any.
	if len(k.password) != 0 {
		passwordBlob, err := windows.UTF16FromString(k.password)
		if err != nil {
			return nil, err
		}
		passwordBlobLen := len(passwordBlob) * 2
		err = nCryptSetProperty(hKey, "SmartCardPin", unsafe.Pointer(&passwordBlob[0]), uint32(passwordBlobLen), ncryptSilentFlag)
		if err != nil {
			return nil, fmt.Errorf("NCryptSetProperty(SmartCardPin) failed: %v", err)
		}
	}

	// Sign
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		return signPSS(k, hKey, msg, hash, pssOpts)
	}
	return signPKCS1v15(k, hKey, msg, hash)
}

// In order to sign with PSS, the flag NCRYPT_TPM_PAD_PSS_IGNORE_SALT must be set
// when calling NCryptSignHash, otherwise, the signature fails with TPM_E_PCP_UNSUPPORTED_PSS_SALT
// whatever the cbSalt value is in bcryptPSSPaddingInfo.
// As a result, when verifying the signature, pssOptions must have saltLength set to rsa.PSSSaltLengthAuto.
// This seems like a bug in PCP KSP PSS Signature code.
func signPSS(priv *pcpRSAPrivateKey, hKey uintptr, msg []byte, hash crypto.Hash, opts *rsa.PSSOptions) ([]byte, error) {

	var saltLength uint32
	var flags uint32
	var paddingInfo bcryptPSSPaddingInfo
	var size uint32
	var sig []byte

	// opts.Hash, if not zero, overrides the passed hash function.
	if opts != nil && opts.Hash != 0 {
		hash = opts.Hash
	}

	// For the moment, setting paddingInfo.CbSalt has no effect as
	// it does not work, and we're using NCRYPT_TPM_PAD_PSS_IGNORE_SALT,
	// which means the PCP KSP ignores this value and always makes use
	// of cbSalt = uint32(priv.Size() - hash.Size()).
	switch opts.SaltLength {
	// PSSSaltLengthAuto causes the salt in a PSS signature to be as large
	// as possible when signing. We derive it from the key's length.
	// Pre-TPM Spec-1.16
	// See https://github.com/tpm2-software/tpm2-pkcs11/issues/417
	case rsa.PSSSaltLengthAuto:
		saltLength = uint32(priv.Size() - hash.Size()) // uint32(priv.Size() - 2 - hash.Size())
		break
	// PSSSaltLengthEqualsHash causes the salt length to equal the length
	// of the hash used in the signature.
	// Post-TPM Spec-1.16
	case rsa.PSSSaltLengthEqualsHash:
		saltLength = uint32(hash.Size())
		break
	default:
		saltLength = uint32(opts.SaltLength)
	}

	// Setup the PSS padding info.
	// For the moment, setting paddingInfo.CbSalt has no effect as
	// it does not work, and we're using NCRYPT_TPM_PAD_PSS_IGNORE_SALT,
	// which means the PCP KSP ignores this value and always makes use
	// of cbSalt = uint32(priv.Size() - hash.Size()).
	paddingInfo.CbSalt = saltLength
	switch hash {
	case crypto.SHA1:
		{
			paddingInfo.PszAlgID, _ = windows.UTF16FromString(bcryptSha1Algorithm)
			break
		}
	case crypto.SHA256:
		{
			paddingInfo.PszAlgID, _ = windows.UTF16FromString(bcryptSha256Algorithm)
			break
		}
	case crypto.SHA384:
		{
			paddingInfo.PszAlgID, _ = windows.UTF16FromString(bcryptSha384Algorithm)
			break
		}
	case crypto.SHA512:
		{
			paddingInfo.PszAlgID, _ = windows.UTF16FromString(bcryptSha512Algorithm)
			break
		}
	default:
		{
			return nil, fmt.Errorf("Unsupported digest algo")
		}
	}

	// If a password is set for the key, set the flag NcryptSilentFlag when signing,
	// meaning no UI should be shown to the user. Therefore, if the password is wrong,
	// the operation will fail silently.
	// Otherwise, if no password is set, do not set the flag, meaning if the key
	// needs a password, a UI will be shown to ask for it.
	flags = bcryptPadPss | ncryptTpmPadPssIgnoreSalt
	if len(priv.password) != 0 {
		flags |= ncryptSilentFlag
	}

	// Sign.
	err := nCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), &msg[0], uint32(len(msg)), nil, 0, &size, flags)
	if err != nil {
		return nil, fmt.Errorf("NCryptSignHash() step 1 failed: %v", err)
	}
	if size == 0 {
		return nil, fmt.Errorf("NCryptSignHash() returned 0 on size read")
	}
	sig = make([]byte, size)
	err = nCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), &msg[0], uint32(len(msg)), &sig[0], size, &size, flags)
	if err != nil {
		return nil, fmt.Errorf("NCryptSignHash() step 2 failed: %v", err)
	}

	return sig, nil
}

func signPKCS1v15(priv *pcpRSAPrivateKey, hKey uintptr, msg []byte, hash crypto.Hash) ([]byte, error) {

	var sig []byte
	var size uint32
	var paddingInfo bcryptPKCS11PaddingInfo
	var flags uint32

	// Setup the PKCS1v15 padding info.
	switch hash {
	case crypto.SHA1:
		{
			paddingInfo.PszAlgID, _ = windows.UTF16FromString(bcryptSha1Algorithm)
			break
		}
	case crypto.SHA256:
		{
			paddingInfo.PszAlgID, _ = windows.UTF16FromString(bcryptSha256Algorithm)
			break
		}
	case crypto.SHA384:
		{
			paddingInfo.PszAlgID, _ = windows.UTF16FromString(bcryptSha384Algorithm)
			break
		}
	case crypto.SHA512:
		{
			paddingInfo.PszAlgID, _ = windows.UTF16FromString(bcryptSha512Algorithm)
			break
		}
	default:
		{
			return nil, fmt.Errorf("Unsupported digest algo")
		}
	}

	// If a password is set for the key, set the flag NcryptSilentFlag when signing,
	// meaning no UI should be shown to the user. Therefore, if the password is wrong,
	// the operation will fail silently.
	// Otherwise, if no password is set, do not set the flag, meaning if the key
	// needs a password, a UI will be shown to ask for it.
	flags = bcryptPadPkcs1
	if len(priv.password) != 0 {
		flags |= ncryptSilentFlag
	}

	// Sign.
	err := nCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), &msg[0], uint32(len(msg)), nil, 0, &size, flags)
	if err != nil {
		return nil, fmt.Errorf("NCryptSignHash() step 1 failed: %v", err)
	}
	sig = make([]byte, size)
	err = nCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), &msg[0], uint32(len(msg)), &sig[0], size, &size, flags)
	if err != nil {
		return nil, fmt.Errorf("NCryptSignHash() step 2 failed: %v", err)
	}

	return sig, nil
}

// GenerateRSAKey generates a new signing RSA PCP Key with the specified name and bit
// length, then returns its corresponding pcpRSAPrivateKey instance.
// If name is empty, it will generate unique random name beforehand.
// If overwrite is set, and if a key with the same name already exists, it will
// be overwritten.
// Usually, supported bit lengths by the TPM chip are 1024 and 2048, but there is
// no restriction on bitLength.
// The key usage is left to be the default one for RSA, which is Sign + Decrypt.
// TODO: Support UI Policies + manually set key usages.
// N.B:
// 	Trying to set NCRYPT_PCP_PSS_SALT_SIZE_PROPERTY("PSS Salt Size") to either
// 	NCRYPT_TPM_PSS_SALT_SIZE_UNKNOWN(0), NCRYPT_TPM_PSS_SALT_SIZE_MAXIMUM(1) or
// 	NCRYPT_TPM_PSS_SALT_SIZE_HASHSIZE(2) always fails with NTE_NOT_SUPPORTED.
func GenerateRSAKey(name string, password string, bitLength int, overwrite bool) (Signer, error) {
	var hProvider uintptr
	var hKey uintptr

	// Get a handle to the PCP KSP
	err := nCryptOpenStorageProvider(&hProvider, pcpProviderName, 0)
	if err != nil {
		return nil, fmt.Errorf("NCryptOpenStorageProvider() failed: %v", err)
	}
	defer nCryptFreeObject(hProvider)

	// If name is empty, generate a unique random one
	if name == "" {
		uuidName, err := uuid.NewRandom()
		if err != nil {
			return nil, fmt.Errorf("uuid.NewRandom() failed: %v", err)
		}
		name = uuidName.String()
	}

	// Start the creation of the key
	if overwrite {
		err = nCryptCreatePersistedKey(hProvider, &hKey, bcryptRsaAlgorithm, name, 0, ncryptOverwriteKeyFlag)
	} else {
		err = nCryptCreatePersistedKey(hProvider, &hKey, bcryptRsaAlgorithm, name, 0, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("NCryptCreatePersistedKey() failed: %v", err)
	}

	// Set the length of the key
	u32BitLength := uint32(bitLength)
	err = nCryptSetProperty(hKey, "Length", unsafe.Pointer(&u32BitLength), uint32(unsafe.Sizeof(u32BitLength)), 0)
	if err != nil {
		return nil, fmt.Errorf("NCryptSetProperty(Length) failed: %v", err)
	}

	// If password is given, set it as NCRYPT_PIN_PROPERTY
	if len(password) != 0 {
		passwordBlob, err := windows.UTF16FromString(password)
		if err != nil {
			return nil, err
		}
		passwordBlobLen := len(passwordBlob) * 2
		err = nCryptSetProperty(hKey, "SmartCardPin", unsafe.Pointer(&passwordBlob[0]), uint32(passwordBlobLen), 0)
		if err != nil {
			return nil, fmt.Errorf("NCryptSetProperty(SmartCardPin) failed: %v", err)
		}
	}

	// Finalize (create) the key
	err = nCryptFinalizeKey(hKey, 0)
	if err != nil {
		return nil, fmt.Errorf("NCryptFinalizeKey() failed: %v", err)
	}
	defer nCryptFreeObject(hKey)

	//	Read key's public part
	pubkeyBytes, _, err := getNCryptBufferPublicKey(hKey)
	if err != nil {
		return nil, fmt.Errorf("getNCryptBufferPublicKey() failed: %v", err)
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
			name:     name,
			password: password,
			pubKey:   publicKey,
		},
	}, nil
}
