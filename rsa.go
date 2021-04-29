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
func (k *pcpRSAPrivateKey) Size() uint32 {
	return uint32((k.pubKey.(*rsa.PublicKey).N.BitLen() + 7) / 8)
}

// Sign is a required method of the crypto.Signer interface.
func (k *pcpRSAPrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	var hProvider uintptr
	var hKey uintptr
	var hash crypto.Hash
	var flags uint32

	// If opts is null or opts.HashFunc is 0, it means msg is not a digest and
	// must be signed directly. This is not recommended except for interoperability.
	// For the moment, we do not support signing arbitrary data (i.e. RSA Raw signature).
	if (opts == nil) || (opts.HashFunc() == 0) {
		return nil, fmt.Errorf("raw signature not supported")
	}
	hash = opts.HashFunc()

	// Get a handle to the PCP KSP.
	_, err = nCryptOpenStorageProvider(&hProvider, msPlatformCryptoProvider, 0)
	if err != nil {
		return nil, err
	}
	defer nCryptFreeObject(hProvider)

	// Try to get a handle to the key by its name.
	if k.localMachine {
		flags |= ncryptMachineKeyFlag
	}
	_, err = nCryptOpenKey(hProvider, &hKey, k.name, 0, flags)
	if err != nil {
		return nil, err
	}
	defer nCryptFreeObject(hKey)

	// Set the key password / pin before signing if any.
	if len(k.password) != 0 {
		passwordBlob, err := utf16BytesFromString(k.password)
		if err != nil {
			return nil, err
		}
		passwordBlobLen := len(passwordBlob)
		_, err = nCryptSetProperty(hKey, ncryptPinProperty, &passwordBlob[0], uint32(passwordBlobLen), ncryptSilentFlag)
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
// when calling NCryptSignHash, otherwise, the signature fails with TPM_E_PCP_UNSUPPORTED_PSS_SALT
// whatever the cbSalt value is in bcryptPSSPaddingInfo.
// As a result, when verifying the signature, pssOptions must have saltLength set to rsa.PSSSaltLengthAuto.
// This seems like a bug in PCP KSP PSS Signature code.
func signPSS(priv *pcpRSAPrivateKey, hKey uintptr, msg []byte, hash crypto.Hash, opts *rsa.PSSOptions) ([]byte, error) {

	var saltLength uint32
	var flags uint32
	var paddingInfo bcryptPssPaddingInfo
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
		saltLength = priv.Size() - uint32(hash.Size()) // uint32(priv.Size() - 2 - hash.Size())
	// PSSSaltLengthEqualsHash causes the salt length to equal the length
	// of the hash used in the signature.
	// Post-TPM Spec-1.16
	case rsa.PSSSaltLengthEqualsHash:
		saltLength = uint32(hash.Size())
	default:
		saltLength = uint32(opts.SaltLength)
	}

	// Setup the PSS padding info.
	// For the moment, setting paddingInfo.CbSalt has no effect as
	// it does not work, and we're using NCRYPT_TPM_PAD_PSS_IGNORE_SALT,
	// which means the PCP KSP ignores this value and always makes use
	// of cbSalt = uint32(priv.Size() - hash.Size()).
	paddingInfo.cbSalt = saltLength
	switch hash {
	case crypto.SHA1:
		{
			paddingInfo.pszAlgId, _ = windows.UTF16PtrFromString(bcryptSha1Algorithm)
			break
		}
	case crypto.SHA256:
		{
			paddingInfo.pszAlgId, _ = windows.UTF16PtrFromString(bcryptSha256Algorithm)
			break
		}
	case crypto.SHA384:
		{
			paddingInfo.pszAlgId, _ = windows.UTF16PtrFromString(bcryptSha384Algorithm)
			break
		}
	case crypto.SHA512:
		{
			paddingInfo.pszAlgId, _ = windows.UTF16PtrFromString(bcryptSha512Algorithm)
			break
		}
	default:
		{
			return nil, fmt.Errorf("unsupported digest algo")
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
	_, err := nCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), &msg[0], uint32(len(msg)), nil, 0, &size, flags)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, fmt.Errorf("nCryptSignHash() returned 0 on size read")
	}
	sig = make([]byte, size)
	_, err = nCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), &msg[0], uint32(len(msg)), &sig[0], size, &size, flags)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func signPKCS1v15(priv *pcpRSAPrivateKey, hKey uintptr, msg []byte, hash crypto.Hash) ([]byte, error) {

	var sig []byte
	var size uint32
	var paddingInfo bcryptPkcs1PaddingInfo
	var flags uint32

	// Setup the PKCS1v15 padding info.
	switch hash {
	case crypto.SHA1:
		{
			paddingInfo.pszAlgId, _ = windows.UTF16PtrFromString(bcryptSha1Algorithm)
			break
		}
	case crypto.SHA256:
		{
			paddingInfo.pszAlgId, _ = windows.UTF16PtrFromString(bcryptSha256Algorithm)
			break
		}
	case crypto.SHA384:
		{
			paddingInfo.pszAlgId, _ = windows.UTF16PtrFromString(bcryptSha384Algorithm)
			break
		}
	case crypto.SHA512:
		{
			paddingInfo.pszAlgId, _ = windows.UTF16PtrFromString(bcryptSha512Algorithm)
			break
		}
	default:
		{
			return nil, fmt.Errorf("unsupported digest algo")
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
	_, err := nCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), &msg[0], uint32(len(msg)), nil, 0, &size, flags)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, fmt.Errorf("nCryptSignHash() returned 0 on size read")
	}
	sig = make([]byte, size)
	_, err = nCryptSignHash(hKey, unsafe.Pointer(&paddingInfo), &msg[0], uint32(len(msg)), &sig[0], size, &size, flags)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// GenerateRSAKey generates a new signing RSA PCP Key with the specified name and bit
// length, then returns its corresponding pcpRSAPrivateKey instance.
// If name is empty, it will generate unique random name beforehand.
// If password is empty, it will generate the key with no PIN / Password, making it
// usable with no authentication.
// If overwrite is set, and if a key with the same name already exists, it will
// be overwritten.
// Usually, supported bit lengths by the TPM chip are 1024 and 2048, but there is
// no restriction on bitLength.
// The key usage is left to be the default one for RSA, which is Sign + Decrypt.
// TODO: Support UI Policies + manually set key usages.
// N.B:
// Trying to set NCRYPT_PCP_PSS_SALT_SIZE_PROPERTY("PSS Salt Size") to either
// NCRYPT_TPM_PSS_SALT_SIZE_UNKNOWN(0), NCRYPT_TPM_PSS_SALT_SIZE_MAXIMUM(1) or
// NCRYPT_TPM_PSS_SALT_SIZE_HASHSIZE(2) always fails with NTE_NOT_SUPPORTED.
func GenerateRSAKey(name string, password string, bitLength uint32, localMachine bool, overwrite bool) (Signer, error) {
	var hProvider uintptr
	var hKey uintptr
	var flags uint32

	// Get a handle to the PCP KSP
	_, err := nCryptOpenStorageProvider(&hProvider, msPlatformCryptoProvider, 0)
	if err != nil {
		return nil, err
	}
	defer nCryptFreeObject(hProvider)

	// Set the flags
	if overwrite {
		flags |= ncryptOverwriteKeyFlag
	}
	if localMachine {
		flags |= ncryptMachineKeyFlag
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
	_, err = nCryptCreatePersistedKey(hProvider, &hKey, bcryptRsaAlgorithm, name, 0, flags)
	if err != nil {
		return nil, err
	}

	// Set the length of the key
	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, bitLength)
	_, err = nCryptSetProperty(hKey, ncryptLengthProperty, &lengthBytes[0], uint32(len(lengthBytes)), 0)
	if err != nil {
		return nil, err
	}

	// If password is given, set it as NCRYPT_PIN_PROPERTY
	if len(password) != 0 {
		passwordBlob, err := utf16BytesFromString(password)
		if err != nil {
			return nil, err
		}
		passwordBlobLen := len(passwordBlob)
		_, err = nCryptSetProperty(hKey, ncryptPinProperty, &passwordBlob[0], uint32(passwordBlobLen), 0)
		if err != nil {
			return nil, err
		}
	}

	// Finalize (create) the key
	_, err = nCryptFinalizeKey(hKey, 0)
	if err != nil {
		return nil, err
	}
	defer nCryptFreeObject(hKey)

	//	Read key's public part
	pubkeyBytes, _, err := getNCryptBufferPublicKey(hKey, bcryptRsapublicBlob, 0)
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
			name:         name,
			password:     password,
			localMachine: localMachine,
			pubKey:       publicKey,
		},
	}, nil
}
