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
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/ElMostafaIdrassi/goncrypt"
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

	var openFlags goncrypt.NcryptFlag
	var flags goncrypt.NcryptFlag
	var b cryptobyte.Builder
	var sig []byte

	// If opts is null or opts.HashFunc is 0, it means msg is not a digest and
	// must be signed directly. This is not recommended except for interoperability.
	// For the moment, we do not support signing arbitrary data (i.e. ECDSA Raw signature).
	if (opts == nil) || (opts.HashFunc() == 0) {
		return nil, fmt.Errorf("raw signature not supported")
	}

	// Get a handle to the PCP KSP
	provider, _, err := goncrypt.OpenProvider(goncrypt.MsPlatformKeyStorageProvider, 0)
	if err != nil {
		return nil, err
	}
	defer provider.Close()

	// Set the opening flags
	if k.passwordDigest != nil {
		openFlags |= goncrypt.NcryptSilentFlag
	}
	if k.isLocalMachine {
		openFlags |= goncrypt.NcryptMachineKeyFlag
	}

	// Set the other flags
	// If a password is set for the key, set the flag NCRYPT_SILENT_FLAG, meaning
	// no UI should be shown to the user. Therefore, if the password is wrong,
	// the operation will fail silently.
	// Otherwise, if no password is set, do not set the flag, meaning a UI might
	// be shown to ask for it if the key needs one.
	if k.passwordDigest != nil {
		flags = goncrypt.NcryptSilentFlag
	}

	// Try to get a handle to the key by its name
	key, _, err := provider.OpenKey(k.name, 0, openFlags)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	// Set the key password / pin before signing if required.
	if k.passwordDigest != nil {
		_, err = key.SetProperty(goncrypt.NcryptPcpUsageauthProperty, k.passwordDigest, flags)
		if err != nil {
			return nil, err
		}
	}

	// Sign
	sig, _, err = key.Sign(nil, msg, flags)
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
// If isLocalMachine is set to true, GenerateRSAKey will generate keys that apply to the
// Local Machine. Otherwise, it will generate keys that apply for the Current User.
//
// The key usage can be set by combining the following flags using the OR operation :
//   - AllowDecrypt
//   - AllowSigning
//   - AllowKeyAgreement
//   - AllowAllUsages
//
// If keyUsage is set to Default instead, the default key usage will be used, which is
// SignOnly for ECDSA keys.
func GenerateECDSAKey(
	name string,
	password string,
	isUICompatible bool,
	isLocalMachine bool,
	curve elliptic.Curve,
	keyUsage KeyUsage,
	overwrite bool,
) (Signer, error) {
	var creationFlags goncrypt.NcryptFlag
	var flags goncrypt.NcryptFlag

	// Check that keyUsage contains a valid combination
	if keyUsage != KeyUsageDefault &&
		keyUsage != KeyUsageAllowAllUsages &&
		(keyUsage & ^(KeyUsageAllowDecrypt|KeyUsageAllowSigning|KeyUsageAllowKeyAgreement)) != 0 {
		return nil, fmt.Errorf("keyUsage parameter contains an unexpected combination of flags (%x)", keyUsage.Value())
	}

	// Get a handle to the PCP KSP
	provider, _, err := goncrypt.OpenProvider(goncrypt.MsPlatformKeyStorageProvider, 0)
	if err != nil {
		return nil, err
	}
	defer provider.Close()

	// Set the creation flags
	if overwrite {
		creationFlags |= goncrypt.NcryptOverwriteKeyFlag
	}
	if isLocalMachine {
		creationFlags |= goncrypt.NcryptMachineKeyFlag
	}

	// Set the other flags
	if len(password) != 0 {
		flags |= goncrypt.NcryptSilentFlag
	}

	// Check the specified curve
	var curveName goncrypt.NcryptAlgorithm
	switch curve {
	case elliptic.P256():
		curveName = goncrypt.NcryptEcdsaP256Algorithm
	case elliptic.P384():
		curveName = goncrypt.NcryptEcdsaP384Algorithm
	case elliptic.P521():
		curveName = goncrypt.NcryptEcdsaP521Algorithm
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

	// If password is given, set it as NCRYPT_PCP_USAGE_AUTH_PROPERTY either :
	//	- after SHA-1 if UI compatibility is required
	//	- or after SHA-256 otherwise
	var passwordDigest []byte
	if len(password) != 0 {
		passwordBlob, err := stringToUtf16Bytes(password)
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
	}

	// Set the key usage.
	var keyUsageBytes []byte
	if keyUsage != 0 {
		keyUsageBytes = make([]byte, 4)
		binary.LittleEndian.PutUint32(keyUsageBytes, keyUsage.Value())
	}

	// Set the properties.
	properties := map[goncrypt.NcryptProperty][]byte{}
	if keyUsageBytes != nil {
		properties[goncrypt.NcryptKeyUsageProperty] = keyUsageBytes
	}
	if passwordDigest != nil {
		properties[goncrypt.NcryptPcpUsageauthProperty] = passwordDigest
	}

	// Create the key.
	key, _, err := provider.CreatePersistedKey(curveName, name, 0, properties, creationFlags, flags, flags)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	//	Read key's public part
	pubkeyBytes, _, err := key.Export(goncrypt.Key{}, goncrypt.NcryptEccPublicBlob, nil, flags)
	if err != nil {
		key.Delete(flags)
		return nil, err
	}

	// Get the path to the PCP file.
	pcpPathBytes, _, err := key.GetProperty(goncrypt.NcryptUniqueNameProperty, goncrypt.NcryptSilentFlag)
	if err != nil {
		key.Delete(flags)
		return nil, err
	}
	pcpPath, err := utf16BytesToString(pcpPathBytes)
	if err != nil {
		key.Delete(flags)
		return nil, err
	}

	// Parse the PCP file.
	// TODO: Here we are silently ignoring the error returned by ParsePCPKeyFile. Change this.
	public, private, digestPolicy, _, _, _ := ParsePCPKeyFile(pcpPath)

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

	// Return *pcpECDSAPrivateKey instance
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

// GenerateECKeyWithUIPolicy is a variant of GenerateECKey that allows to specify
// the key's UI policy instead of the key's password.
func GenerateECKeyWithUIPolicy(
	name string,
	uiPolicy UIPolicy,
	isLocalMachine bool,
	curve elliptic.Curve,
	keyUsage KeyUsage,
	overwrite bool,
) (Signer, error) {
	var creationFlags goncrypt.NcryptFlag
	var flags goncrypt.NcryptFlag
	var ncryptUiPolicy goncrypt.NcryptUiPolicy

	// Check that keyUsage contains a valid combination
	if keyUsage != KeyUsageDefault &&
		keyUsage != KeyUsageAllowAllUsages &&
		(keyUsage & ^(KeyUsageAllowDecrypt|KeyUsageAllowSigning|KeyUsageAllowKeyAgreement)) != 0 {
		return nil, fmt.Errorf("keyUsage parameter contains an unexpected combination of flags (%x)", keyUsage.Value())
	}

	// Check that uiPolicy is valid
	if uiPolicy != UIPolicyNoConsent &&
		uiPolicy != UIPolicyConsentWithOptionalPIN &&
		uiPolicy != UIPolicyConsentWithMandatoryPIN &&
		uiPolicy != UIPolicyConsentWithMandatoryFingerprint {
		return nil, fmt.Errorf("uiPolicy parameter contains an unexpected value (%x)", uiPolicy.Value())
	}

	// Setup the Ncrypt UI Policy
	ncryptUiPolicy.Version = 1
	ncryptUiPolicy.FriendlyName = name
	if uiPolicy == UIPolicyConsentWithOptionalPIN {
		ncryptUiPolicy.Flags = goncrypt.NcryptUiProtectKeyFlag
		ncryptUiPolicy.Description = "This key requires usage consent and an optional PIN."
	} else if uiPolicy == UIPolicyConsentWithMandatoryPIN {
		ncryptUiPolicy.Flags = goncrypt.NcryptUiForceHighProtectionFlag
		ncryptUiPolicy.Description = "This key requires usage consent and a mandatory PIN."
	} else if uiPolicy == UIPolicyConsentWithMandatoryFingerprint {
		ncryptUiPolicy.Flags = goncrypt.NcryptUiFingerprintProtectionFlag
		ncryptUiPolicy.Description = "This key requires usage consent and a mandatory Fingerprint."
	}
	uiPolicyBytes, err := ncryptUiPolicy.Serialize()
	if err != nil {
		return nil, fmt.Errorf("ncryptUiPolicy.Serialize() failed: %v", err)
	}

	// Get a handle to the PCP KSP
	provider, _, err := goncrypt.OpenProvider(goncrypt.MsPlatformKeyStorageProvider, 0)
	if err != nil {
		return nil, err
	}
	defer provider.Close()

	// Set the creation flags
	if overwrite {
		creationFlags |= goncrypt.NcryptOverwriteKeyFlag
	}
	if isLocalMachine {
		creationFlags |= goncrypt.NcryptMachineKeyFlag
	}

	// Check the specified curve
	var curveName goncrypt.NcryptAlgorithm
	switch curve {
	case elliptic.P256():
		curveName = goncrypt.NcryptEcdsaP256Algorithm
	case elliptic.P384():
		curveName = goncrypt.NcryptEcdsaP384Algorithm
	case elliptic.P521():
		curveName = goncrypt.NcryptEcdsaP521Algorithm
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

	// Set the key usage.
	var keyUsageBytes []byte
	if keyUsage != KeyUsageDefault {
		keyUsageBytes = make([]byte, 4)
		binary.LittleEndian.PutUint32(keyUsageBytes, uint32(keyUsage))
	}

	// Set the properties.
	properties := map[goncrypt.NcryptProperty][]byte{
		goncrypt.NcryptUiPolicyProperty: uiPolicyBytes,
	}
	if keyUsageBytes != nil {
		properties[goncrypt.NcryptKeyUsageProperty] = keyUsageBytes
	}

	// Create the key.
	key, _, err := provider.CreatePersistedKey(curveName, name, 0, properties, creationFlags, flags, flags)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	// Read key's public part
	pubkeyBytes, _, err := key.Export(goncrypt.Key{}, goncrypt.NcryptEccPublicBlob, nil, flags)
	if err != nil {
		key.Delete(flags)
		return nil, err
	}

	// Get the path to the PCP file.
	pcpPathBytes, _, err := key.GetProperty(goncrypt.NcryptUniqueNameProperty, goncrypt.NcryptSilentFlag)
	if err != nil {
		key.Delete(flags)
		return nil, err
	}
	pcpPath, err := utf16BytesToString(pcpPathBytes)
	if err != nil {
		key.Delete(flags)
		return nil, err
	}

	// Get the usage auth.
	pcpUsageAuthBytes, _, err := key.GetProperty(goncrypt.NcryptPcpUsageauthProperty, goncrypt.NcryptSilentFlag)
	if err != nil {
		key.Delete(flags)
		return nil, err
	}

	// Parse the PCP file.
	// TODO: Here we are silently ignoring the error returned by ParsePCPKeyFile. Change this.
	public, private, digestPolicy, _, _, _ := ParsePCPKeyFile(pcpPath)

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

	// Return *pcpECDSAPrivateKey instance
	return &pcpECDSAPrivateKey{
		pcpPrivateKey{
			name:           name,
			passwordDigest: pcpUsageAuthBytes,
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
