// Copyright (c) 2020-2025, El Mostafa IDRASSI.
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

	"github.com/ElMostafaIdrassi/goncrypt"
	"github.com/google/go-tpm/legacy/tpm2"
)

func Initialize(customLogger goncrypt.Logger) (errRet error) {
	return goncrypt.Initialize(customLogger)
}

func Finalize() {
	goncrypt.Finalize()
}

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
	KeyUsage() KeyUsage

	// IsLocalMachine returns whether the key applies to the Local Machine or to the Current User.
	IsLocalMachine() bool

	// Path returns the path to the PCP key file on disk.
	Path() string

	// TPMTPublicKey returns the TPMT_PUBLIC from the PCP key file
	TPMTPublicKey() *tpm2.Public

	// TPM2BPrivateKey returns the TPM2B_PRIVATE from the PCP key file
	TPM2BPrivateKey() []byte

	// TPMLDigestPolicy returns the TPML_DIGEST from the PCP key file
	TPMLDigestPolicy() *tpm2.TPMLDigest

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
	keyUsage       KeyUsage         // keyUsage is the PCP key usage.
	isLocalMachine bool             // isLocalMachine determines whether the key applies to the Local Machine or to the Current User.
	path           string           // path is the PCP key file path.

	public       *tpm2.Public     // TPMT_PUBLIC
	private      []byte           // TPM2B_PRIVATE
	digestPolicy *tpm2.TPMLDigest // TPML_DIGEST
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
func (k pcpPrivateKey) KeyUsage() KeyUsage {
	return k.keyUsage
}

// IsLocalMachine returns whether the key applies to the Local Machine or to the Current User.
func (k pcpPrivateKey) IsLocalMachine() bool {
	return k.isLocalMachine
}

// Path returns the path to the PCP key file on disk.
func (k pcpPrivateKey) Path() string {
	return k.path
}

func (k pcpPrivateKey) TPMTPublicKey() *tpm2.Public {
	return k.public
}

func (k pcpPrivateKey) TPM2BPrivateKey() []byte {
	return k.private
}

func (k pcpPrivateKey) TPMLDigestPolicy() *tpm2.TPMLDigest {
	return k.digestPolicy
}

// Delete deletes the PCP key.
func (k pcpPrivateKey) Delete() error {
	var flags goncrypt.NcryptFlag

	// Get a handle to the PCP KSP
	provider, _, err := goncrypt.OpenProvider(goncrypt.MsPlatformKeyStorageProvider, 0)
	if err != nil {
		return err
	}
	defer provider.Close()

	// Set the flags
	flags = goncrypt.NcryptSilentFlag
	if k.isLocalMachine {
		flags |= goncrypt.NcryptMachineKeyFlag
	}

	// Try to get a handle to the key by its name
	key, _, err := provider.OpenKey(k.name, 0, flags)
	if err != nil {
		return err
	}

	// Try to delete the key
	_, err = key.Delete(0)
	if err != nil {
		key.Close()
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
//   - PCP keys created with a password set in the Windows UI,
//   - PCP keys created with a password set programmatically using NCRYPT_PIN_PORPERTY.
//
// A password set via the UI prompt is transformed internally into its
// SHA-1 digest, while a password set programmatically via NCRYPT_PIN_PROPERTY is
// transformed internally into its SHA-256 digest.
// Therefore, if isUICompatible is set to true, we will store the SHA-1 of the password,
// while we will store its SHA-256 if isUICompatible is set to false.
// Note that, if the key was created with a password set via the Windows UI prompt,
// isUICompatible should be set to true.
//
// If isLocalMachine is set to true, the search will look for keys that apply to the
// Local Machine. Otherwise, it will look for keys that apply for the Current User.
//
// After all operations are done on the resulting key, its handle should be
// freed by calling the Close() function on the key.
func FindKey(name string, password string, isUICompatible bool, isLocalMachine bool) (Signer, error) {
	var flags goncrypt.NcryptFlag
	var publicKey crypto.PublicKey
	var passwordDigest []byte

	// Get a handle to the PCP KSP
	provider, _, err := goncrypt.OpenProvider(goncrypt.MsPlatformKeyStorageProvider, 0)
	if err != nil {
		return nil, err
	}
	defer provider.Close()

	// Set the flags
	flags = goncrypt.NcryptSilentFlag
	if isLocalMachine {
		flags |= goncrypt.NcryptMachineKeyFlag
	}

	// Try to get a handle to the key by its name
	key, _, err := provider.OpenKey(name, 0, flags)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	// Get key's algorithm
	algBytes, _, err := key.GetProperty(goncrypt.NcryptAlgorithmGroupProperty, goncrypt.NcryptSilentFlag)
	if err != nil {
		return nil, err
	}
	alg, err := utf16BytesToString(algBytes)
	if err != nil {
		return nil, err
	}

	// Get key's usage
	var keyUsage KeyUsage
	usageBytes, _, err := key.GetProperty(goncrypt.NcryptKeyUsageProperty, goncrypt.NcryptSilentFlag)
	if err != nil {
		return nil, err
	}
	if len(usageBytes) != 4 {
		return nil, fmt.Errorf("GetProperty() returned unexpected output: expected 4 bytes, got %v bytes", len(usageBytes))
	}
	usage := binary.LittleEndian.Uint32(usageBytes)
	keyUsage.fromNcryptFlag(goncrypt.NcryptKeyUsagePropertyFlag(usage))

	// Get the password digest.
	if password != "" {
		passwordBlob, err := stringToUtf16Bytes(password)
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

	// Get the path to the PCP file.
	pcpPathBytes, _, err := key.GetProperty(goncrypt.NcryptUniqueNameProperty, goncrypt.NcryptSilentFlag)
	if err != nil {
		return nil, err
	}
	pcpPath, err := utf16BytesToString(pcpPathBytes)
	if err != nil {
		return nil, err
	}

	// Parse the PCP file.
	// TODO: Here we are silently ignoring the error returned by ParsePCPKeyFile. Change this.
	public, private, digestPolicy, _, _, _ := ParsePCPKeyFile(pcpPath)

	// Read key's public part
	var pubkeyBytes []byte
	var isRSA bool
	if alg == string(goncrypt.NcryptRsaAlgorithm) {
		pubkeyBytes, _, err = key.Export(goncrypt.Key{}, goncrypt.NcryptRsaPublicBlob, nil, 0)
		isRSA = true
	} else if alg == string(goncrypt.NcryptEcdsaAlgorithm) {
		pubkeyBytes, _, err = key.Export(goncrypt.Key{}, goncrypt.NcryptEccPublicBlob, nil, 0)
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
				keyUsage:       keyUsage,
				isLocalMachine: isLocalMachine,
				path:           pcpPath,
				public:         public,
				private:        private,
				digestPolicy:   digestPolicy,
			},
		}, nil
	} else {

		// Construct ecdsa.PublicKey from BCRYPT_ECCPUBLIC_BLOB
		var keyByteSize int
		var keyCurve elliptic.Curve

		magic := binary.LittleEndian.Uint32(pubkeyBytes[0:4])
		if magic == uint32(goncrypt.BcryptEcdsaPublicP256Magic) {
			keyByteSize = 32
			keyCurve = elliptic.P256()
		} else if magic == uint32(goncrypt.BcryptEcdsaPublicP384Magic) {
			keyByteSize = 48
			keyCurve = elliptic.P384()
		} else if magic == uint32(goncrypt.BcryptEcdsaPublicP521Magic) {
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
				keyUsage:       keyUsage,
				isLocalMachine: isLocalMachine,
				path:           pcpPath,
				public:         public,
				private:        private,
				digestPolicy:   digestPolicy,
			},
		}, nil
	}
}

// GetKeys tries to retrieve all existing PCP keys.
//
// If isLocalMachine is set to true, the search will retrieve the keys that apply to the
// Local Machine. Otherwise, it will retrieve the keys that apply for the Current User.
func GetKeys(isLocalMachine bool) ([]Signer, error) {
	var flags goncrypt.NcryptFlag
	var err error

	keys := make([]Signer, 0)

	// Open a handle to the "Microsoft Platform Crypto Provider" provider.
	provider, _, err := goncrypt.OpenProvider(goncrypt.MsPlatformKeyStorageProvider, 0)
	if err != nil {
		return nil, err
	}
	defer provider.Close()

	// Set the flags
	flags = goncrypt.NcryptSilentFlag
	if isLocalMachine {
		flags |= goncrypt.NcryptMachineKeyFlag
	}

	// Retrieve all keys.
	keysInfo, _, err := provider.EnumKeys("", flags)
	if err != nil {
		return nil, err
	}
	for _, keyInfo := range keysInfo {
		var pubkeyBytes []byte
		var isRSA bool

		// Open a handle to the key
		key, _, err := provider.OpenKey(keyInfo.Name, 0, flags)
		if err != nil {
			return nil, err
		}
		defer key.Close()

		// Get key's usage
		var keyUsage KeyUsage
		usageBytes, _, err := key.GetProperty(goncrypt.NcryptKeyUsageProperty, goncrypt.NcryptSilentFlag)
		if err != nil {
			return nil, err
		}
		if len(usageBytes) != 4 {
			return nil, fmt.Errorf("GetProperty() returned unexpected output: expected 4 bytes, got %v bytes", len(usageBytes))
		}
		usage := binary.LittleEndian.Uint32(usageBytes)
		keyUsage.fromNcryptFlag(goncrypt.NcryptKeyUsagePropertyFlag(usage))

		// Get the path to the PCP file.
		pcpPathBytes, _, err := key.GetProperty(goncrypt.NcryptUniqueNameProperty, goncrypt.NcryptSilentFlag)
		if err != nil {
			return nil, err
		}
		pcpPath, err := utf16BytesToString(pcpPathBytes)
		if err != nil {
			return nil, err
		}

		// Parse the PCP file.
		// TODO: Here we are silently ignoring the error returned by ParsePCPKeyFile. Change this.
		public, private, digestPolicy, _, _, _ := ParsePCPKeyFile(pcpPath)

		// Read key's public part
		if keyInfo.Alg == goncrypt.NcryptRsaAlgorithm {
			pubkeyBytes, _, err = key.Export(goncrypt.Key{}, goncrypt.NcryptRsaPublicBlob, nil, 0)
			isRSA = true
		} else if keyInfo.Alg == goncrypt.NcryptEcdsaAlgorithm {
			pubkeyBytes, _, err = key.Export(goncrypt.Key{}, goncrypt.NcryptEccPublicBlob, nil, 0)
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
					name:           keyInfo.Name,
					passwordDigest: nil,
					pubKey:         publicKey,
					keyUsage:       keyUsage,
					isLocalMachine: isLocalMachine,
					path:           pcpPath,
					public:         public,
					private:        private,
					digestPolicy:   digestPolicy,
				},
			})
		} else {

			// Construct ecdsa.PublicKey from BCRYPT_ECCPUBLIC_BLOB
			var keyByteSize int
			var keyCurve elliptic.Curve

			magic := binary.LittleEndian.Uint32(pubkeyBytes[0:4])
			if magic == uint32(goncrypt.BcryptEcdsaPublicP256Magic) {
				keyByteSize = 32
				keyCurve = elliptic.P256()
			} else if magic == uint32(goncrypt.BcryptEcdsaPublicP384Magic) {
				keyByteSize = 48
				keyCurve = elliptic.P384()
			} else if magic == uint32(goncrypt.BcryptEcdsaPublicP521Magic) {
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
					name:           keyInfo.Name,
					passwordDigest: nil,
					pubKey:         publicKey,
					keyUsage:       keyUsage,
					isLocalMachine: isLocalMachine,
					path:           pcpPath,
					public:         public,
					private:        private,
					digestPolicy:   digestPolicy,
				},
			})
		}
	}

	return keys, nil
}

// SealDataWithTPM seals the passed data using the TPM.
//
// The data is sealed using the TPM's SRK (Storage Root Key) and can only be
// unsealed on the same machine, by any user.
//
// If a password is provided, it is used as an additional TPM Sealing Password
// and the sealed data can only be unsealed if the same password is provided,
// on the same machine, by any user.
func SealDataWithTPM(dataToSeal []byte, password string) ([]byte, error) {
	var buf goncrypt.BcryptBuffer
	var bufDesc goncrypt.BcryptBufferDesc
	var padding unsafe.Pointer
	var err error

	// Open a handle to the "Microsoft Platform Crypto Provider" provider.
	provider, _, err := goncrypt.OpenProvider(goncrypt.MsPlatformKeyStorageProvider, 0)
	if err != nil {
		return nil, err
	}
	defer provider.Close()

	// Open a handle to the "Microsoft Platform Crypto Provider" RSA Sealing key.
	key, _, err := provider.OpenKey(goncrypt.TpmRsaSrkSealKey, 0, goncrypt.NcryptSilentFlag)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	// If we have a password, set it up in a buffer.
	if password != "" {
		passwordBytes := []byte(password)

		buf.BufferLen = uint32(len(passwordBytes))
		buf.Buffer = &passwordBytes[0]
		buf.BufferType = uint32(goncrypt.NcryptBufferTpmSealPassword)

		bufs := make([]goncrypt.BcryptBuffer, 1)
		bufs[0] = buf
		bufDesc.Version = uint32(goncrypt.BcryptBufferVersion)
		bufDesc.BuffersLen = 1
		bufDesc.Buffers = &bufs[0]

		padding = unsafe.Pointer(&bufDesc)
	}

	// Seal the data.
	sealedData, _, err := key.Encrypt(dataToSeal, padding, goncrypt.NcryptSealingFlag)
	if err != nil {
		return nil, err
	}

	return sealedData, nil
}

// UnsealDataWithTPM unseals the passed data using the TPM.
//
// The data is unsealed using the TPM's SRK (Storage Root Key) on the same
// machine it was sealed on, by any user.
//
// If a password was used to seal the data, it must be provided to unseal it.
func UnsealDataWithTPM(dataToUnseal []byte, password string) ([]byte, error) {
	var buf goncrypt.BcryptBuffer
	var bufDesc goncrypt.BcryptBufferDesc
	var padding unsafe.Pointer
	var err error

	// Open a handle to the "Microsoft Platform Crypto Provider" provider.
	provider, _, err := goncrypt.OpenProvider(goncrypt.MsPlatformKeyStorageProvider, 0)
	if err != nil {
		return nil, err
	}
	defer provider.Close()

	// Open a handle to the "Microsoft Platform Crypto Provider" RSA Sealing key.
	key, _, err := provider.OpenKey(goncrypt.TpmRsaSrkSealKey, 0, goncrypt.NcryptSilentFlag)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	// If we have a password, set it up in a buffer.
	if password != "" {
		passwordBytes := []byte(password)

		buf.BufferLen = uint32(len(passwordBytes))
		buf.Buffer = &passwordBytes[0]
		buf.BufferType = uint32(goncrypt.NcryptBufferTpmSealPassword)

		bufs := make([]goncrypt.BcryptBuffer, 1)
		bufs[0] = buf
		bufDesc.Version = uint32(goncrypt.BcryptBufferVersion)
		bufDesc.BuffersLen = 1
		bufDesc.Buffers = &bufs[0]

		padding = unsafe.Pointer(&bufDesc)
	}

	// Unseal the data.
	unsealedData, _, err := key.Decrypt(dataToUnseal, padding, goncrypt.NcryptSealingFlag)
	if err != nil {
		return nil, err
	}

	return unsealedData, nil
}
