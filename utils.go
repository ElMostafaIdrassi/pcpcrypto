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
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pcpProviderName = "Microsoft Platform Crypto Provider"
	cryptENotFound  = 0x80092004 // From winerror.h.
)

//	From C:\Program Files (x86)\Windows Kits\10\Include\10.0.18362.0\shared\bcrypt.h
const (
	bcryptNoKeyValidation = 0x00000008

	//
	// RSA padding schemes.
	//
	bcryptPadNone                 = 0x00000001
	bcryptPadPkcs1                = 0x00000002 // BCryptEncrypt/Decrypt BCryptSignHash/VerifySignature
	bcryptPadOaep                 = 0x00000004 // BCryptEncrypt/Decrypt
	bcryptPadPss                  = 0x00000008 // BCryptSignHash/VerifySignature
	bcryptPadPkcs1OptionalHashOid = 0x00000010 // BCryptVerifySignature

	//
	// Common algorithm identifiers.
	//
	bcryptRsaAlgorithm             = "RSA"
	bcryptRsaSignAlgorithm         = "RSA_SIGN"
	bcryptDhAlgorithm              = "DH"
	bcryptDsaAlgorithm             = "DSA"
	bcryptRc2Algorithm             = "RC2"
	bcryptRc4Algorithm             = "RC4"
	bcryptAesAlgorithm             = "AES"
	bcryptDesAlgorithm             = "DES"
	bcryptDesxAlgorithm            = "DESX"
	bcrypt3DesAlgorithm            = "3DES"
	bcrypt3Des112Algorithm         = "3DES_112"
	bcryptMd2Algorithm             = "MD2"
	bcryptMd4Algorithm             = "MD4"
	bcryptMd5Algorithm             = "MD5"
	bcryptSha1Algorithm            = "SHA1"
	bcryptSha256Algorithm          = "SHA256"
	bcryptSha384Algorithm          = "SHA384"
	bcryptSha512Algorithm          = "SHA512"
	bcryptAesGmacAlgorithm         = "AES-GMAC"
	bcryptAesCmacAlgorithm         = "AES-CMAC"
	bcryptEcdsaP256Algorithm       = "ECDSA_P256"
	bcryptEcdsaP384Algorithm       = "ECDSA_P384"
	bcryptEcdsaP521Algorithm       = "ECDSA_P521"
	bcryptEcdhP256Algorithm        = "ECDH_P256"
	bcryptEcdhP384Algorithm        = "ECDH_P384"
	bcryptEcdhP521Algorithm        = "ECDH_P521"
	bcryptRngAlgorithm             = "RNG"
	bcryptRngFips186DsaAlgorithm   = "FIPS186DSARNG"
	bcryptRngDualEcAlgorithm       = "DUALECRNG"
	bcryptSp800108CtrHmacAlgorithm = "SP800_108_CTR_HMAC"
	bcryptSp80056AConcatAlgorithm  = "SP800_56A_CONCAT"
	bcryptPbkdf2Algorithm          = "PBKDF2"
	bcryptCapiKdfAlgorithm         = "CAPI_KDF"
	bcryptTls11KdfAlgorithm        = "TLS1_1_KDF"
	bcryptTls12KdfAlgorithm        = "TLS1_2_KDF"
	bcryptEcdsaAlgorithm           = "ECDSA"
	bcryptEcdhAlgorithm            = "ECDH"
	bcryptXtsAesAlgorithm          = "XTS-AES"
	bcryptHkdfAlgorithm            = "HKDF"

	//
	// Structures used to represent key blobs.
	//
	bcryptPublicKeyBlob  = "PUBLICBLOB"
	bcryptPrivateKeyBlob = "PRIVATEBLOB"

	// The BCRYPT_RSAPUBLIC_BLOB and BCRYPT_RSAPRIVATE_BLOB blob types are used
	// to transport plaintext RSA keys. These blob types will be supported by
	// all RSA primitive providers.
	// The BCRYPT_RSAPRIVATE_BLOB includes the following values:
	// 		Magic 					(BcryptRsaprivateMagic : 4 bytes)
	// 		Key Bit Size			(4 bytes)
	// 		Public Exponent Size	(4 bytes)
	// 		Modulus Size			(4 bytes)
	// 		Prime 1 Size			(4 bytes)
	// 		Prime 2 Size			(4 bytes)
	// 		Public Exponent			(Public Exponent Size bytes)
	// 		Modulus					(Modulus Size bytes)
	// 		Prime1					(Prime 1 Size bytes)
	// 		Prime2					(Prime 2 Size bytes)
	// The BCRYPT_RSAPUBLIC_BLOB includes the following values (in Little Endian):
	// 		Magic 					(BcryptRsapublicMagic : 4 bytes)
	// 		Key Bit Size			(4 bytes)
	// 		Public Exponent Size	(4 bytes)
	// 		Modulus Size			(4 bytes)
	// 		Public Exponent			(Public Exponent Size bytes)
	// 		Modulus					(Modulus Size bytes)
	bcryptRsapublicBlob   = "RSAPUBLICBLOB"
	bcryptRsaprivateBlob  = "RSAPRIVATEBLOB"
	bcryptRsapublicMagic  = 0x31415352 // RSA1
	bcryptRsaprivateMagic = 0x32415352 // RSA2

	// The BCRYPT_ECCPUBLIC_BLOB and BCRYPT_ECCPRIVATE_BLOB blob types are used
	// to transport plaintext ECC keys. These blob types will be supported by
	// all ECC primitive providers.
	// The BCRYPT_ECCPRIVATE_BLOB includes the following values:
	// 		Magic 					(4 bytes)
	// 		Key Byte Size			(4 bytes)
	// 		X						(Key Byte Size bytes)
	// 		Y						(Key Byte Size bytes)
	// 		D						(Key Byte Size bytes)
	// The BCRYPT_ECCPUBLIC_BLOB includes the following values (in Little Endian):
	// 		Magic 					(4 bytes)
	// 		Key Byte Size			(4 bytes)
	// 		x						(Key Byte Size bytes)
	// 		Y						(Key Byte Size bytes)
	bcryptEccpublicBlob         = "ECCPUBLICBLOB"
	bcryptEccprivateBlob        = "ECCPRIVATEBLOB"
	bcryptEcdsaPublicP256Magic  = 0x31534345 // ECS1
	bcryptEcdsaPrivateP256Magic = 0x32534345 // ECS2
	bcryptEcdsaPublicP384Magic  = 0x33534345 // ECS3
	bcryptEcdsaPrivateP384Magic = 0x34534345 // ECS4
	bcryptEcdsaPublicP521Magic  = 0x35534345 // ECS5
	bcryptEcdsaPrivateP521Magic = 0x36534345 // ECS6
)

type bcryptOEAPPaddingInfo struct {
	PszAlgID []uint16
	PbLabel  []byte
	CbLabel  uint32
}
type bcryptPKCS11PaddingInfo struct {
	PszAlgID []uint16
}
type bcryptPSSPaddingInfo struct {
	PszAlgID []uint16
	CbSalt   uint32
}

//	From C:\Program Files (x86)\Windows Kits\10\Include\10.0.18362.0\um\ncrypt.h
const (

	//
	// NCrypt API Flags
	//
	ncryptNoPaddingFlag              = 0x00000001 // NCryptEncrypt/Decrypt
	ncryptPadPkcs1Flag               = 0x00000002 // NCryptEncrypt/Decrypt NCryptSignHash/VerifySignature
	ncryptPadOaepFlag                = 0x00000004 // BCryptEncrypt/Decrypt
	ncryptPadPssFlag                 = 0x00000008 // BCryptSignHash/VerifySignature
	ncryptPadCipherFlag              = 0x00000010 // NCryptEncrypt/Decrypt
	ncryptSealingFlag                = 0x00000100 // NCryptEncrypt/Decrypt for sealing
	ncryptRegisterNotifyFlag         = 0x00000001 // NCryptNotifyChangeKey
	ncryptUnregisterNotifyFlag       = 0x00000002 // NCryptNotifyChangeKey
	ncryptNoKeyValidation            = bcryptNoKeyValidation
	ncryptMachineKeyFlag             = 0x00000020 // same as CAPI CRYPT_MACHINE_KEYSET
	ncryptSilentFlag                 = 0x00000040 // same as CAPI CRYPT_SILENT
	ncryptOverwriteKeyFlag           = 0x00000080
	ncryptWriteKeyToLegacyStoreFlag  = 0x00000200
	ncryptDoNotFinalizeFlag          = 0x00000400
	ncryptExportLegacyFlag           = 0x00000800
	ncryptTreatNistAsGenericEccFlag  = 0x00002000
	ncryptNoCachedPassword           = 0x00004000
	ncryptProtectToLocalSystem       = 0x00008000
	ncryptPersistOnlyFlag            = 0x40000000
	ncryptPersistFlag                = 0x80000000
	ncryptPreferVirtualIsolationFlag = 0x00010000 // NCryptCreatePersistedKey NCryptImportKey
	ncryptUseVirtualIsolationFlag    = 0x00020000 // NCryptCreatePersistedKey NCryptImportKey
	ncryptUsePerBootKeyFlag          = 0x00040000 // NCryptCreatePersistedKey NCryptImportKey

	//
	// NCryptOpenStorageProvider flags
	//
	ncryptIgnoreDeviceStateFlag = 0x00001000 // NCryptOpenStorageProvider

	//
	// The following flags are used with NCRYPT_CIPHER_PADDING_INFO
	//
	ncryptCipherNoPaddingFlag    = 0x00000000
	ncryptCipherBlockPaddingFlag = 0x00000001
	ncryptCipherOtherPaddingFlag = 0x00000002

	//
	// BCRYPT_PCP_KEY_USAGE_POLICY values
	//
	ncryptTpm12Provider          = 0x00010000
	ncryptPcpSignatureKey        = 0x00000001
	ncryptPcpEncryptionKey       = 0x00000002
	ncryptPcpGenericKey          = ncryptPcpSignatureKey | ncryptPcpEncryptionKey
	ncryptPcpStorageKey          = 0x00000004
	ncryptPcpIdentityKey         = 0x00000008
	ncryptPcpHmacverificationKey = 0x00000010

	//
	// Common algorithm identifiers.
	//
	ncryptRsaAlgorithm             = bcryptRsaAlgorithm
	ncryptRsaSignAlgorithm         = bcryptRsaSignAlgorithm
	ncryptDhAlgorithm              = bcryptDhAlgorithm
	ncryptDsaAlgorithm             = bcryptDsaAlgorithm
	ncryptMd2Algorithm             = bcryptMd2Algorithm
	ncryptMd4Algorithm             = bcryptMd4Algorithm
	ncryptMd5Algorithm             = bcryptMd5Algorithm
	ncryptSha1Algorithm            = bcryptSha1Algorithm
	ncryptSha256Algorithm          = bcryptSha256Algorithm
	ncryptSha384Algorithm          = bcryptSha384Algorithm
	ncryptSha512Algorithm          = bcryptSha512Algorithm
	ncryptEcdsaP256Algorithm       = bcryptEcdsaP256Algorithm
	ncryptEcdsaP384Algorithm       = bcryptEcdsaP384Algorithm
	ncryptEcdsaP521Algorithm       = bcryptEcdsaP521Algorithm
	ncryptEcdhP256Algorithm        = bcryptEcdhP256Algorithm
	ncryptEcdhP384Algorithm        = bcryptEcdhP384Algorithm
	ncryptEcdhP521Algorithm        = bcryptEcdhP521Algorithm
	ncryptAesAlgorithm             = bcryptAesAlgorithm
	ncryptRc2Algorithm             = bcryptRc2Algorithm
	ncrypt3DesAlgorithm            = bcrypt3DesAlgorithm
	ncryptDesAlgorithm             = bcryptDesAlgorithm
	ncryptDesxAlgorithm            = bcryptDesxAlgorithm
	ncrypt3Des112Algorithm         = bcrypt3Des112Algorithm
	ncryptSp800108CtrHmacAlgorithm = bcryptSp800108CtrHmacAlgorithm
	ncryptSp80056AConcatAlgorithm  = bcryptSp80056AConcatAlgorithm
	ncryptPbkdf2Algorithm          = bcryptPbkdf2Algorithm
	ncryptCapiKdfAlgorithm         = bcryptCapiKdfAlgorithm
	ncryptEcdsaAlgorithm           = bcryptEcdsaAlgorithm
	ncryptEcdhAlgorithm            = bcryptEcdhAlgorithm
	ncryptKeyStorageAlgorithm      = "KEY_STORAGE"

	//
	// This algorithm is not supported by any BCrypt provider. This identifier is for creating
	// persistent stored HMAC keys in the TPM KSP.
	//
	ncryptHmacSha256Algorithm = "HMAC-SHA256"

	//
	// Algorithm groups (Values of NCRYPT_ALGORITHM_GROUP_PROPERTY).
	//
	ncryptRsaAlgorithmGroup   = ncryptRsaAlgorithm
	ncryptDhAlgorithmGroup    = ncryptDhAlgorithm
	ncryptDsaAlgorithmGroup   = ncryptDsaAlgorithm
	ncryptEcdsaAlgorithmGroup = "ECDSA"
	ncryptEcdhAlgorithmGroup  = "ECDH"
	ncryptAesAlgorithmGroup   = ncryptAesAlgorithm
	ncryptRc2AlgorithmGroup   = ncryptRc2Algorithm
	ncryptDesAlgorithmGroup   = "DES"
	ncryptKeyDerivationGroup  = "KEY_DERIVATION"

	ncryptTpmPadPssIgnoreSalt = 0x00000020 // NCryptSignHash
)

// DLL references.
var (
	nCrypt                         = windows.MustLoadDLL("ncrypt.dll")
	nCryptCreateClaimProc          = nCrypt.MustFindProc("NCryptCreateClaim")
	nCryptCreatePersistedKeyProc   = nCrypt.MustFindProc("NCryptCreatePersistedKey")
	nCryptDecryptProc              = nCrypt.MustFindProc("NCryptDecrypt")
	nCryptDeleteKeyProc            = nCrypt.MustFindProc("NCryptDeleteKey")
	nCryptDeriveKeyProc            = nCrypt.MustFindProc("NCryptDeriveKey")
	nCryptEncryptProc              = nCrypt.MustFindProc("NCryptEncrypt")
	nCryptEnumAlgorithmsProc       = nCrypt.MustFindProc("NCryptEnumAlgorithms")
	nCryptEnumKeysProc             = nCrypt.MustFindProc("NCryptEnumKeys")
	nCryptEnumStorageProvidersProc = nCrypt.MustFindProc("NCryptEnumStorageProviders")
	nCryptExportKeyProc            = nCrypt.MustFindProc("NCryptExportKey")
	nCryptFinalizeKeyProc          = nCrypt.MustFindProc("NCryptFinalizeKey")
	nCryptFreeBufferProc           = nCrypt.MustFindProc("NCryptFreeBuffer")
	nCryptFreeObjectProc           = nCrypt.MustFindProc("NCryptFreeObject")
	nCryptGetPropertyProc          = nCrypt.MustFindProc("NCryptGetProperty")
	nCryptImportKeyProc            = nCrypt.MustFindProc("NCryptImportKey")
	nCryptIsAlgSupportedProc       = nCrypt.MustFindProc("NCryptIsAlgSupported")
	nCryptIsKeyHandleProc          = nCrypt.MustFindProc("NCryptIsKeyHandle")
	nCryptKeyDerivationProc        = nCrypt.MustFindProc("NCryptKeyDerivation")
	nCryptNotifyChangeKeyProc      = nCrypt.MustFindProc("NCryptNotifyChangeKey")
	nCryptOpenKeyProc              = nCrypt.MustFindProc("NCryptOpenKey")
	nCryptOpenStorageProviderProc  = nCrypt.MustFindProc("NCryptOpenStorageProvider")
	nCryptSecretAgreementProc      = nCrypt.MustFindProc("NCryptSecretAgreement")
	nCryptSetPropertyProc          = nCrypt.MustFindProc("NCryptSetProperty")
	nCryptSignHashProc             = nCrypt.MustFindProc("NCryptSignHash")
	nCryptTranslateHandleProc      = nCrypt.MustFindProc("NCryptTranslateHandle")
	nCryptVerifyClaimProc          = nCrypt.MustFindProc("NCryptVerifyClaim")
	nCryptVerifySignatureProc      = nCrypt.MustFindProc("NCryptVerifySignature")

	crypt32                            = windows.MustLoadDLL("crypt32.dll")
	crypt32CertEnumCertificatesInStore = crypt32.MustFindProc("CertEnumCertificatesInStore")
	crypt32CertCloseStore              = crypt32.MustFindProc("CertCloseStore")
)

// Error codes.
var (
	isReadyErrors = map[uint32]string{
		0x00000002: "Platform restart is required (shutdown).",
		0x00000004: "Platform restart is required (reboot).",
		0x00000008: "The TPM is already owned.",
		0x00000010: "Physical presence is required to provision the TPM.",
		0x00000020: "The TPM is disabled or deactivated.",
		0x00000040: "TPM ownership was taken.",
		0x00000080: "An endorsement key exists in the TPM.",
		0x00000100: "The TPM owner authorization is not properly stored in the registry.",
		0x00000200: "The Storage Root Key (SRK) authorization value is not all zeros.",
		0x00000800: "The operating system's registry information about the TPM’s Storage Root Key does not match the TPM Storage Root Key.",
		0x00001000: "The TPM permanent flag to allow reading of the Storage Root Key public value is not set.",
		0x00002000: "The monotonic counter incremented during boot has not been created.",
		0x00020000: "Windows Group Policy is configured to not store any TPM owner authorization so the TPM cannot be fully ready.",
		0x00040000: "The EK Certificate was not read from the TPM NV Ram and stored in the registry.",
		0x00080000: "The TCG event log is empty or cannot be read.",
		0x00100000: "The TPM is not owned.",
		0x00200000: "An error occurred, but not specific to a particular task.",
		0x00400000: "The device lock counter has not been created.",
		0x00800000: "The device identifier has not been created.",
	}
	tpmErrNums = map[uint32]string{
		0x80280001: "TPM_E_AUTHFAI",
		0x80280002: "TPM_E_BADINDEX",
		0x80280003: "TPM_E_BAD_PARAMETER",
		0x80280004: "TPM_E_AUDITFAILURE",
		0x80280005: "TPM_E_CLEAR_DISABLED",
		0x80280006: "TPM_E_DEACTIVATED",
		0x80280007: "TPM_E_DISABLED",
		0x80280008: "TPM_E_DISABLED_CMD",
		0x80280009: "TPM_E_FAI",
		0x8028000A: "TPM_E_BAD_ORDINA",
		0x8028000B: "TPM_E_INSTALL_DISABLED",
		0x8028000C: "TPM_E_INVALID_KEYHANDLE",
		0x8028000D: "TPM_E_KEYNOTFOUND",
		0x8028000E: "TPM_E_INAPPROPRIATE_ENC",
		0x8028000F: "TPM_E_MIGRATEFAI",
		0x80280010: "TPM_E_INVALID_PCR_INFO",
		0x80280011: "TPM_E_NOSPACE",
		0x80280012: "TPM_E_NOSRK",
		0x80280013: "TPM_E_NOTSEALED_BLOB",
		0x80280014: "TPM_E_OWNER_SET",
		0x80280015: "TPM_E_RESOURCES",
		0x80280016: "TPM_E_SHORTRANDOM",
		0x80280017: "TPM_E_SIZE",
		0x80280018: "TPM_E_WRONGPCRVA",
		0x80280019: "TPM_E_BAD_PARAM_SIZE",
		0x8028001A: "TPM_E_SHA_THREAD",
		0x8028001B: "TPM_E_SHA_ERROR",
		0x8028001C: "TPM_E_FAILEDSELFTEST",
		0x8028001D: "TPM_E_AUTH2FAI",
		0x8028001E: "TPM_E_BADTAG",
		0x8028001F: "TPM_E_IOERROR",
		0x80280020: "TPM_E_ENCRYPT_ERROR",
		0x80280021: "TPM_E_DECRYPT_ERROR",
		0x80280022: "TPM_E_INVALID_AUTHHANDLE",
		0x80280023: "TPM_E_NO_ENDORSEMENT",
		0x80280024: "TPM_E_INVALID_KEYUSAGE",
		0x80280025: "TPM_E_WRONG_ENTITYTYPE",
		0x80280026: "TPM_E_INVALID_POSTINIT",
		0x80280027: "TPM_E_INAPPROPRIATE_SIG",
		0x80280028: "TPM_E_BAD_KEY_PROPERTY",
		0x80280029: "TPM_E_BAD_MIGRATION",
		0x8028002A: "TPM_E_BAD_SCHEME",
		0x8028002B: "TPM_E_BAD_DATASIZE",
		0x8028002C: "TPM_E_BAD_MODE",
		0x8028002D: "TPM_E_BAD_PRESENCE",
		0x8028002E: "TPM_E_BAD_VERSION",
		0x8028002F: "TPM_E_NO_WRAP_TRANSPORT",
		0x80280030: "TPM_E_AUDITFAIL_UNSUCCESSFU",
		0x80280031: "TPM_E_AUDITFAIL_SUCCESSFU",
		0x80280032: "TPM_E_NOTRESETABLE",
		0x80280033: "TPM_E_NOTLOCA",
		0x80280034: "TPM_E_BAD_TYPE",
		0x80280035: "TPM_E_INVALID_RESOURCE",
		0x80280036: "TPM_E_NOTFIPS",
		0x80280037: "TPM_E_INVALID_FAMILY",
		0x80280038: "TPM_E_NO_NV_PERMISSION",
		0x80280039: "TPM_E_REQUIRES_SIGN",
		0x8028003A: "TPM_E_KEY_NOTSUPPORTED",
		0x8028003B: "TPM_E_AUTH_CONFLICT",
		0x8028003C: "TPM_E_AREA_LOCKED",
		// TODO: Finish NVRAM error codes.
		0x80280049: "TPM_E_NOOPERATOR",
		0x8028004A: "TPM_E_RESOURCEMISSING",
		0x8028004B: "TPM_E_DELEGATE_LOCK",
		0x8028004C: "TPM_E_DELEGATE_FAMILY",
		0x8028004D: "TPM_E_DELEGATE_ADMIN",
		0x8028004E: "TPM_E_TRANSPORT_NOTEXCLUSIVE",
		0x8028004F: "TPM_E_OWNER_CONTRO",
		0x80280050: "TPM_E_DAA_RESOURCES",
		// TODO: Finish DAA error codes.
		0x80280058: "TPM_E_BAD_HANDLE",
		0x80280059: "TPM_E_BAD_DELEGATE",
		0x8028005A: "TPM_E_BADCONTEXT",
		0x8028005B: "TPM_E_TOOMANYCONTEXTS",
		0x8028005C: "TPM_E_MA_TICKET_SIGNATURE",
		0x8028005D: "TPM_E_MA_DESTINATION",
		0x8028005E: "TPM_E_MA_SOURCE",
		0x8028005F: "TPM_E_MA_AUTHORITY",
		0x80280061: "TPM_E_PERMANENTEK",
		0x80280062: "TPM_E_BAD_SIGNATURE",
		0x80280063: "TPM_E_NOCONTEXTSPACE",
		0x80280400: "TPM_E_COMMAND_BLOCKED",
		0x80280401: "TPM_E_INVALID_HANDLE",
		0x80280402: "TPM_E_DUPLICATE_VHANDLE",
		0x80280403: "TPM_E_EMBEDDED_COMMAND_BLOCKED",
		0x80280404: "TPM_E_EMBEDDED_COMMAND_UNSUPPORTED",
		0x80280800: "TPM_E_RETRY",
		0x80280801: "TPM_E_NEEDS_SELFTEST",
		0x80280802: "TPM_E_DOING_SELFTEST",
		0x80280803: "TPM_E_DEFEND_LOCK_RUNNING",
		0x80284001: "TBS_E_INTERNAL_ERROR",
		0x80284002: "TBS_E_BAD_PARAMETER",
		0x80284003: "TBS_E_INVALID_OUTPUT_POINTER",
		0x80284004: "TBS_E_INVALID_CONTEXT",
		0x80284005: "TBS_E_INSUFFICIENT_BUFFER",
		0x80284006: "TBS_E_IOERROR",
		0x80284007: "TBS_E_INVALID_CONTEXT_PARAM",
		0x80284008: "TBS_E_SERVICE_NOT_RUNNING",
		0x80284009: "TBS_E_TOO_MANY_TBS_CONTEXTS",
		0x8028400A: "TBS_E_TOO_MANY_RESOURCES",
		0x8028400B: "TBS_E_SERVICE_START_PENDING",
		0x8028400C: "TBS_E_PPI_NOT_SUPPORTED",
		0x8028400D: "TBS_E_COMMAND_CANCELED",
		0x8028400E: "TBS_E_BUFFER_TOO_LARGE",
		0x8028400F: "TBS_E_TPM_NOT_FOUND",
		0x80284010: "TBS_E_SERVICE_DISABLED",
		0x80284011: "TBS_E_NO_EVENT_LOG",
		0x80284012: "TBS_E_ACCESS_DENIED",
		0x80284013: "TBS_E_PROVISIONING_NOT_ALLOWED",
		0x80284014: "TBS_E_PPI_FUNCTION_UNSUPPORTED",
		0x80284015: "TBS_E_OWNERAUTH_NOT_FOUND",
		0x80284016: "TBS_E_PROVISIONING_INCOMPLETE",
		// TODO: TPMAPI & TPMSIMP error codes.
		0x80290401: "TPM_E_PCP_DEVICE_NOT_READY",
		0x80290402: "TPM_E_PCP_INVALID_HANDLE",
		0x80290403: "TPM_E_PCP_INVALID_PARAMETER",
		0x80290404: "TPM_E_PCP_FLAG_NOT_SUPPORTED",
		0x80290405: "TPM_E_PCP_NOT_SUPPORTED",
		0x80290406: "TPM_E_PCP_BUFFER_TOO_SMAL",
		0x80290407: "TPM_E_PCP_INTERNAL_ERROR",
		0x80290408: "TPM_E_PCP_AUTHENTICATION_FAILED",
		0x80290409: "TPM_E_PCP_AUTHENTICATION_IGNORED",
		0x8029040A: "TPM_E_PCP_POLICY_NOT_FOUND",
		0x8029040B: "TPM_E_PCP_PROFILE_NOT_FOUND",
		0x8029040C: "TPM_E_PCP_VALIDATION_FAILED",
		0x80090009: "NTE_BAD_FLAGS",
		0x80090026: "NTE_INVALID_HANDLE",
		0x80090027: "NTE_INVALID_PARAMETER",
		0x80090029: "NTE_NOT_SUPPORTED",
	}
)

type bCryptBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   *byte
}

type bCryptBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *bCryptBuffer
}

type nCryptAlgorithmName struct {
	pszName         []uint16
	dwClass         uint32
	dwAlgOperations uint32
	dwFlags         uint32
}

func maybeWinErr(errNo uintptr) error {
	if code, known := tpmErrNums[uint32(errNo)]; known {
		return fmt.Errorf("tpm or subsystem failure: %s", code)
	}
	return nil
}

// Transforms a []byte which contains a wide char string in LE
// into its []uint16 corresponding representation,
// then returns the UTF-8 encoding of the UTF-16 sequence,
// with a terminating NUL removed.
func utf16ToString(buf []byte) (string, error) {
	b := make([]uint16, len(buf)/2)
	// LPCSTR (Windows' representation of utf16) is always little endian.
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &b); err != nil {
		return "", err
	}
	return windows.UTF16ToString(b), nil
}

// Returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func utf16FromString(str string) ([]uint16, error) {
	return windows.UTF16FromString(str)
}

// getNCryptBufferProperty is a helper to read a byte slice from a NCrypt handle property
// using NCryptGetProperty.
func getNCryptBufferProperty(hnd uintptr, field string) ([]byte, error) {
	var size uint32

	wideField, err := utf16FromString(field)
	if err != nil {
		return nil, err
	}

	r, _, msg := nCryptGetPropertyProc.Call(hnd, uintptr(unsafe.Pointer(&wideField[0])), 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, fmt.Errorf("NCryptGetProperty() returned %d,%X (%v) for key %q on size read", size, r, msg, field)
	}
	if size == 0 {
		return nil, fmt.Errorf("NCryptGetProperty() returned 0 for key %q on size read", field)
	}

	buff := make([]byte, size)
	r, _, msg = nCryptGetPropertyProc.Call(hnd, uintptr(unsafe.Pointer(&wideField[0])), uintptr(unsafe.Pointer(&buff[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, fmt.Errorf("NCryptGetProperty() returned %X (%v) for key %q on data read", r, msg, field)
	}
	return buff, nil
}

// getNCryptBufferPublicKey is a helper to read the public key as a byte slice from a NCrypt handle
// using NCryptExportKey. The output is a blob : BCRYPT_RSAPUBLIC_BLOB for RSA keys, and
// BCRYPT_ECCPUBLIC_BLOB for ECDSA keys.
// Only RSA and ECDSA keys are supported for the moment.
func getNCryptBufferPublicKey(hnd uintptr) ([]byte, bool, error) {
	var size uint32
	var pubkeyName []uint16

	alg, err := getNCryptBufferProperty(hnd, "Algorithm Group")
	if err != nil {
		return nil, false, fmt.Errorf("Failed to read NCRYPT_ALGORITHM_GROUP_PROPERTY: %v", err)
	}

	algStr, err := utf16ToString(alg)
	if err != nil {
		return nil, false, err
	}
	if algStr == ncryptRsaAlgorithm {
		pubkeyName, err = utf16FromString(bcryptRsapublicBlob)
		if err != nil {
			return nil, false, err
		}
	} else if algStr == ncryptEcdsaAlgorithm {
		pubkeyName, err = utf16FromString(bcryptEccpublicBlob)
		if err != nil {
			return nil, false, err
		}
	} else {
		return nil, false, fmt.Errorf("Unsupported algo: only RSA and ECDSA keys are supported")
	}

	r, _, msg := nCryptExportKeyProc.Call(hnd, 0, uintptr(unsafe.Pointer(&pubkeyName[0])), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, false, fmt.Errorf("NCryptExportKey() returned %d,%X (%v) on size read", size, r, msg)
	}
	if size == 0 {
		return nil, false, fmt.Errorf("NCryptExportKey() returned 0 on size read")
	}

	buff := make([]byte, size)
	r, _, msg = nCryptExportKeyProc.Call(hnd, 0, uintptr(unsafe.Pointer(&pubkeyName[0])), 0, uintptr(unsafe.Pointer(&buff[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, false, fmt.Errorf("NCryptExportKey() returned %X (%v) on data read", r, msg)
	}
	return buff, algStr == ncryptRsaAlgorithm, nil
}

/* **************************************************************************** */

// pszAlgId = Common algorithm identifiers.
func nCryptCreatePersistedKey(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	hKey *uintptr, /* NCRYPT_KEY_HANDLE* */
	pszAlgID string, /* LPCWSTR */
	pszKeyName string, /* LPCWSTR */
	dwLegacyKeySpec uint32, /* DWORD */
	dwFlags uint32, /* DWORD */
) error {
	utf16AlgID, err := utf16FromString(pszAlgID)
	if err != nil {
		return err
	}

	utf16KeyName, err := utf16FromString(pszKeyName)
	if err != nil {
		return err
	}

	r, _, msg := nCryptCreatePersistedKeyProc.Call(
		uintptr(hProvider),
		uintptr(unsafe.Pointer(hKey)),
		uintptr(unsafe.Pointer(&utf16AlgID[0])),
		uintptr(unsafe.Pointer(&utf16KeyName[0])),
		uintptr(dwLegacyKeySpec),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptCreatePersistedKey() returned %X: %v", r, msg)
	}

	return nil
}

func nCryptDecrypt(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	pbInput *byte, /* PBYTE */
	cbInput uint32, /* DWORD */
	pPaddingInfo unsafe.Pointer, /* VOID* */
	pbOutput *byte, /* PBYTE */
	cbOutput uint32, /* DWORD */
	pcbResult *uint32, /* DWORD* */
	dwFlags uint32, /* DWORD */
) error {
	r, _, msg := nCryptDecryptProc.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(pbInput)),
		uintptr(cbInput),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(pbOutput)),
		uintptr(cbOutput),
		uintptr(unsafe.Pointer(pcbResult)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptDecrypt() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptDeleteKey(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	dwFlags uint32, /* DWORD */
) error {
	r, _, msg := nCryptDeleteKeyProc.Call(
		uintptr(hKey),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptDeleteKey() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptDeriveKey(
	hSharedSecret uintptr, /* NCRYPT_SECRET_HANDLE */
	pwszKDF string, /* LPCWSTR */
	pParameterList *bCryptBufferDesc, /* NCryptBufferDesc* */
	pbDerivedKey *byte, /* PBYTE */
	cbDerivedKey uint32, /* DWORD */
	pcbResult *uint32, /* DWORD* */
	dwFlags uint32, /* DWORD */
) error {
	utf16KDF, err := utf16FromString(pwszKDF)
	if err != nil {
		return err
	}

	r, _, msg := nCryptDeriveKeyProc.Call(
		uintptr(hSharedSecret),
		uintptr(unsafe.Pointer(&utf16KDF[0])),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(pbDerivedKey)),
		uintptr(cbDerivedKey),
		uintptr(unsafe.Pointer(pcbResult)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptDeriveKey() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptEncrypt(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	pbInput *byte, /* PBYTE */
	cbInput uint32, /* DWORD */
	pPaddingInfo unsafe.Pointer, /* VOID* */
	pbOutput *byte, /* PBYTE */
	cbOutput uint32, /* DWORD */
	pcbResult *uint32, /* DWORD* */
	dwFlags uint32, /* DWORD */
) error {
	r, _, msg := nCryptEncryptProc.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(pbInput)),
		uintptr(cbInput),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(pbOutput)),
		uintptr(cbOutput),
		uintptr(unsafe.Pointer(pcbResult)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptEncrypt() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptExportKey(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	hExportKey uintptr, /* NCRYPT_KEY_HANDLE */
	pszBlobType string, /* LPCWSTR */
	pParameterList *bCryptBufferDesc, /* NCryptBufferDesc* */
	pbOutput *byte, /* PBYTE */
	cbOutput uint32, /* DWORD */
	pcbResult *uint32, /* DWORD */
	dwFlags uint32, /* DWORD */
) error {
	utf16BlobType, err := utf16FromString(pszBlobType)
	if err != nil {
		return err
	}

	r, _, msg := nCryptExportKeyProc.Call(
		uintptr(hKey),
		uintptr(hExportKey),
		uintptr(unsafe.Pointer(&utf16BlobType[0])),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(pbOutput)),
		uintptr(cbOutput),
		uintptr(unsafe.Pointer(pcbResult)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptExportKey() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptFinalizeKey(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	dwFlags uint32, /* DWORD */
) error {
	r, _, msg := nCryptFinalizeKeyProc.Call(
		uintptr(hKey),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptFinalizeKey() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptFreeBuffer(
	pvInput unsafe.Pointer, /* PVOID */
) error {
	r, _, msg := nCryptFreeBufferProc.Call(
		uintptr(pvInput),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptFreeBuffer() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptFreeObject(
	hObject uintptr, /* NCRYPT_HANDLE */
) error {
	r, _, msg := nCryptFreeObjectProc.Call(
		uintptr(hObject),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptFreeObject() returned %X, %v", r, msg)
	}
	return nil
}

func nCryptGetProperty(
	hObject uintptr, /* NCRYPT_HANDLE */
	pszProperty string, /* LPCWSTR */
	pbOutput *byte, /* PBYTE */
	cbOutput uint32, /* DWORD */
	pcbResult *uint32, /* DWORD* */
	dwFlags uint32, /* DWORD */
) error {
	utf16Property, err := utf16FromString(pszProperty)
	if err != nil {
		return err
	}

	r, _, msg := nCryptGetPropertyProc.Call(
		uintptr(hObject),
		uintptr(unsafe.Pointer(&utf16Property[0])),
		uintptr(unsafe.Pointer(pbOutput)),
		uintptr(cbOutput),
		uintptr(unsafe.Pointer(pcbResult)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptGetProperty() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptImportKey(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	hImportKey uintptr, /* NCRYPT_KEY_HANDLE */
	pszBlobType string, /* LPCWSTR */
	pParameterList *bCryptBufferDesc, /* NCryptBufferDesc* */
	phKey *uintptr, /* NCRYPT_KEY_HANDLE */
	pbData *byte, /* PBYTE */
	cbData uint32, /* DWORD */
	dwFlags uint32, /* DWORD */
) error {
	utf16BlobType, err := utf16FromString(pszBlobType)
	if err != nil {
		return err
	}

	r, _, msg := nCryptImportKeyProc.Call(
		uintptr(hProvider),
		uintptr(hImportKey),
		uintptr(unsafe.Pointer(&utf16BlobType[0])),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(phKey)),
		uintptr(unsafe.Pointer(pbData)),
		uintptr(cbData),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptImportKey() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptIsAlgSupported(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	pszAlgID string, /* LPCWSTR */
	dwFlags uint32, /* DWORD */
) error {
	utf16AlgID, err := utf16FromString(pszAlgID)
	if err != nil {
		return err
	}

	r, _, msg := nCryptIsAlgSupportedProc.Call(
		uintptr(hProvider),
		uintptr(unsafe.Pointer(&utf16AlgID[0])),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptIsAlgSupported() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptIsKeyHandle(
	hKey uintptr, /* NCRYPT_PROV_HANDLE */
) bool {
	r, _, _ := nCryptIsKeyHandleProc.Call(
		uintptr(hKey),
	)
	return r != 0
}

func nCryptKeyDerivation(
	hKey uintptr, /* NCRYPT_PROV_HANDLE */
	pParameterList *bCryptBufferDesc, /* NCryptBufferDesc* */
	pbDerivedKey *byte, /* PUCHAR */
	cbDerivedKey uint32, /* DWORD */
	pcbResult *uint32, /* DWORD */
	dwFlags uint32, /* ULONG */
) error {
	r, _, msg := nCryptKeyDerivationProc.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(pbDerivedKey)),
		uintptr(cbDerivedKey),
		uintptr(unsafe.Pointer(pcbResult)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptKeyDerivation() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptOpenKey(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	phKey *uintptr, /* NCRYPT_KEY_HANDLE* */
	pszKeyName string, /* LPCWSTR */
	dwLegacyKeySpec uint32, /* DWORD */
	dwFlags uint32, /* DWORD */
) error {
	utf16KeyName, err := utf16FromString(pszKeyName)
	if err != nil {
		return err
	}

	r, _, msg := nCryptOpenKeyProc.Call(
		uintptr(hProvider),
		uintptr(unsafe.Pointer(phKey)),
		uintptr(unsafe.Pointer(&utf16KeyName[0])),
		uintptr(dwLegacyKeySpec),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptOpenKey() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptOpenStorageProvider(
	phProvider *uintptr, /* NCRYPT_PROV_HANDLE* */
	pszProviderName string, /* LPCWSTR */
	dwFlags uint32, /* DWORD */
) error {
	utf16ProviderName, err := utf16FromString(pszProviderName)
	if err != nil {
		return err
	}

	r, _, msg := nCryptOpenStorageProviderProc.Call(
		uintptr(unsafe.Pointer(phProvider)),
		uintptr(unsafe.Pointer(&utf16ProviderName[0])),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptOpenStorageProvider() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptSetProperty(
	hObject uintptr, /* NCRYPT_HANDLE */
	pszProperty string, /* LPCWSTR */
	pbInput unsafe.Pointer, /* PBYTE */
	cbInput uint32, /* DWORD */
	dwFlags uint32, /* DWORD */
) error {
	utf16Property, err := utf16FromString(pszProperty)
	if err != nil {
		return err
	}

	r, _, msg := nCryptSetPropertyProc.Call(
		uintptr(hObject),
		uintptr(unsafe.Pointer(&utf16Property[0])),
		uintptr(pbInput),
		uintptr(cbInput),
		uintptr(dwFlags),
	)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptSetProperty() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptSignHash(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	pPaddingInfo unsafe.Pointer, /* VOID* */
	pbHashValue *byte, /* PBYTE */
	cbHashValue uint32, /* DWORD */
	pbSignature *byte, /* PBYTE */
	cbSignature uint32, /* DWORD */
	pcbResult *uint32, /* DWORD* */
	dwFlags uint32, /* DWORD */
) error {
	r, _, msg := nCryptSignHashProc.Call(
		uintptr(hKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(pbHashValue)),
		uintptr(cbHashValue),
		uintptr(unsafe.Pointer(pbSignature)),
		uintptr(cbSignature),
		uintptr(unsafe.Pointer(pcbResult)),
		uintptr(dwFlags),
	)

	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return fmt.Errorf("NCryptSignHash() returned %X: %v", r, msg)
	}
	return nil
}

func nCryptVerifySignature(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	pPaddingInfo unsafe.Pointer, /* VOID* */
	pbHashValue *byte, /* PBYTE */
	cbHashValue uint32, /* DWORD */
	pbSignature *byte, /* PBYTE */
	cbSignature uint32, /* DWORD */
	dwFlags uint32, /* DWORD */
) error {
	status, _, _ := nCryptVerifySignatureProc.Call(
		uintptr(hKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(pbHashValue)),
		uintptr(cbHashValue),
		uintptr(unsafe.Pointer(pbSignature)),
		uintptr(cbSignature),
		uintptr(dwFlags),
	)

	if status != 0 {
		return fmt.Errorf("NCryptVerifySignature() failed with error code %v", status)
	}

	return nil
}
