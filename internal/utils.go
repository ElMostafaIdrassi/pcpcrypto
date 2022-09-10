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

package internal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//////////////////////////////////////////////////////////////////////////////////////
// BCrypt header content.
// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\shared\bcrypt.h
//////////////////////////////////////////////////////////////////////////////////////

const (

	//
	//  Alignment macros
	//
	//
	// BCRYPT_OBJECT_ALIGNMENT must be a power of 2
	// We align all our internal data structures to 16 to
	// allow fast XMM memory accesses.
	// BCrypt callers do not need to take any alignment precautions.
	//
	BcryptObjectAlignment = 16

	//
	// DeriveKey KDF Types
	//
	BcryptKdfHash           = "HASH"
	BcryptKdfHmac           = "HMAC"
	BcryptKdfTlsPrf         = "TLS_PRF"
	BcryptKdfSp80056aConcat = "SP800_56A_CONCAT"
	BcryptKdfRawSecret      = "TRUNCATE"
	BcryptKdfHkdf           = "HKDF"

	//
	// DeriveKey KDF BufferTypes
	//
	// For BCRYPT_KDF_HASH and BCRYPT_KDF_HMAC operations, there may be an arbitrary
	// number of KDF_SECRET_PREPEND and KDF_SECRET_APPEND buffertypes in the
	// parameter list.  The BufferTypes are processed in order of appearence
	// within the parameter list.
	//
	KdfHashAlgorithm  = 0x0
	KdfSecretPrepend  = 0x1
	KdfSecretAppend   = 0x2
	KdfHmacKey        = 0x3
	KdfTlsPrfLabel    = 0x4
	KdfTlsPrfSeed     = 0x5
	KdfSecretHandle   = 0x6
	KdfTlsPrfProtocol = 0x7
	KdfAlgorithmid    = 0x8
	KdfPartyuinfo     = 0x9
	KdfPartyvinfo     = 0xA
	KdfSupppubinfo    = 0xB
	KdfSuppprivinfo   = 0xC
	KdfLabel          = 0xD
	KdfContext        = 0xE
	KdfSalt           = 0xF
	KdfIterationCount = 0x10

	//
	//
	// Parameters for BCrypt(/NCrypt)KeyDerivation:
	// Generic parameters:
	// KDF_GENERIC_PARAMETER and KDF_HASH_ALGORITHM are the generic parameters that can be passed for the following KDF algorithms:
	// BCRYPT/NCRYPT_SP800108_CTR_HMAC_ALGORITHM
	//      KDF_GENERIC_PARAMETER = KDF_LABEL||0x00||KDF_CONTEXT
	// BCRYPT/NCRYPT_SP80056A_CONCAT_ALGORITHM
	//      KDF_GENERIC_PARAMETER = KDF_ALGORITHMID || KDF_PARTYUINFO || KDF_PARTYVINFO {|| KDF_SUPPPUBINFO } {|| KDF_SUPPPRIVINFO }
	// BCRYPT/NCRYPT_PBKDF2_ALGORITHM
	//      KDF_GENERIC_PARAMETER = KDF_SALT
	// BCRYPT/NCRYPT_CAPI_KDF_ALGORITHM
	//      KDF_GENERIC_PARAMETER = Not used
	// BCRYPT/NCRYPT_TLS1_1_KDF_ALGORITHM
	//      KDF_GENERIC_PARAMETER = Not used
	// BCRYPT/NCRYPT_TLS1_2_KDF_ALGORITHM
	//      KDF_GENERIC_PARAMETER = Not used
	// BCRYPT/NCRYPT_HKDF_ALGORITHM
	//      KDF_GENERIC_PARAMETER = Not used
	//
	// KDF specific parameters:
	// For BCRYPT/NCRYPT_SP800108_CTR_HMAC_ALGORITHM:
	//      KDF_HASH_ALGORITHM, KDF_LABEL and KDF_CONTEXT are required
	// For BCRYPT/NCRYPT_SP80056A_CONCAT_ALGORITHM:
	//      KDF_HASH_ALGORITHM, KDF_ALGORITHMID, KDF_PARTYUINFO, KDF_PARTYVINFO are required
	//      KDF_SUPPPUBINFO, KDF_SUPPPRIVINFO are optional
	// For BCRYPT/NCRYPT_PBKDF2_ALGORITHM
	//      KDF_HASH_ALGORITHM is required
	//      KDF_ITERATION_COUNT, KDF_SALT are optional
	//      Iteration count, (if not specified) will default to 10,000
	// For BCRYPT/NCRYPT_CAPI_KDF_ALGORITHM
	//      KDF_HASH_ALGORITHM is required
	// For BCRYPT/NCRYPT_TLS1_1_KDF_ALGORITHM
	//      KDF_TLS_PRF_LABEL is required
	//      KDF_TLS_PRF_SEED is required
	// For BCRYPT/NCRYPT_TLS1_2_KDF_ALGORITHM
	//      KDF_HASH_ALGORITHM is required
	//      KDF_TLS_PRF_LABEL is required
	//      KDF_TLS_PRF_SEED is required
	// For BCRYPT/NCRYPT_HKDF_ALGORITHM
	//      KDF_HKDF_INFO is optional
	//
	KdfGenericParameter = 0x11
	KdfKeybitlength     = 0x12
	KdfHkdfSalt         = 0x13 // This is used only for testing purposes
	KdfHkdfInfo         = 0x14

	//
	// DeriveKey Flags:
	//
	// KDF_USE_SECRET_AS_HMAC_KEY_FLAG causes the secret agreement to serve also
	// as the HMAC key.  If this flag is used, the KDF_HMAC_KEY parameter should
	// NOT be specified.
	//
	KdfUseSecretAsHmacKeyFlag                = 0x1
	BcryptAuthenticatedCipherModeInfoVersion = 1
	BcryptAuthModeChainCallsFlag             = 0x00000001
	BcryptAuthModeInProgressFlag             = 0x00000002

	//
	// BCrypt String Properties
	//
	// BCrypt(Import/Export)Key BLOB types
	BcryptOpaqueKeyBlob  = "OpaqueKeyBlob"
	BcryptKeyDataBlob    = "KeyDataBlob"
	BcryptAesWrapKeyBlob = "Rfc3565KeyWrapBlob"

	// BCryptGetProperty strings
	BcryptObjectLength       = "ObjectLength"
	BcryptAlgorithmName      = "AlgorithmName"
	BcryptProviderHandle     = "ProviderHandle"
	BcryptChainingMode       = "ChainingMode"
	BcryptBlockLength        = "BlockLength"
	BcryptKeyLength          = "KeyLength"
	BcryptKeyObjectLength    = "KeyObjectLength"
	BcryptKeyStrength        = "KeyStrength"
	BcryptKeyLengths         = "KeyLengths"
	BcryptBlockSizeList      = "BlockSizeList"
	BcryptEffectiveKeyLength = "EffectiveKeyLength"
	BcryptHashLength         = "HashDigestLength"
	BcryptHashOidList        = "HashOIDList"
	BcryptPaddingSchemes     = "PaddingSchemes"
	BcryptSignatureLength    = "SignatureLength"
	BcryptHashBlockLength    = "HashBlockLength"
	BcryptAuthTagLength      = "AuthTagLength"
	BcryptPrimitiveType      = "PrimitiveType"
	BcryptIsKeyedHash        = "IsKeyedHash"
	BcryptIsReusableHash     = "IsReusableHash"
	BcryptMessageBlockLength = "MessageBlockLength"
	BcryptPublicKeyLength    = "PublicKeyLength"
	// Additional BCryptGetProperty strings for the RNG Platform Crypto Provider
	BcryptPcpPlatformTypeProperty    = "PCP_PLATFORM_TYPE"
	BcryptPcpProviderVersionProperty = "PCP_PROVIDER_VERSION"
	BcryptMultiObjectLength          = "MultiObjectLength"
	BcryptIsIfxTpmWeakKey            = "IsIfxTpmWeakKey"

	//
	// Additional properties for the HKDF on BCRYPT_KEY_HANDLE (and
	// BCRYPT_SECRET_HANDLE). Both the hash algorithm property and
	// one of the "Finalize" properties are required for the key
	// (or secret) to be usable.
	//
	// When the available inputs are the input keying material (IKM)
	// and the salt then the "SALT_AND_FINALIZE" path should be used:
	//  - First the function which creates the key (or secret) takes
	//  as input the IKM.
	//  - Then the hash algorithm should be set via the BCRYPT_HKDF_HASH_ALGORITHM
	//  property on BCryptSetProperty.
	//  - Finally the salt is input via the BCRYPT_HKDF_SALT_AND_FINALIZE
	//  property. The salt parameter is optional; thus the property input
	//  is allowed to be NULL.
	//
	// When the available input is the pseudorandom key (PRK) then
	// the "PRK_AND_FINALIZE" path should be used:
	//  - First the function which creates the key (or secret) takes
	//  as input the PRK.
	//  - Then the hash algorithm should be set via the BCRYPT_HKDF_HASH_ALGORITHM
	//  property on BCryptSetProperty.
	//  - Finally the key (or secret) is finalized via the
	//  BCRYPT_HKDF_PRK_AND_FINALIZE property. In this case the input property
	//  must be NULL since the PRK was already passed in.
	//
	// After setting one of the two "Finalize" properties the key
	// (or the secret) is finalized and can be used to derive the
	// HKDF output.
	//
	BcryptHkdfHashAlgorithm   = "HkdfHashAlgorithm"
	BcryptHkdfSaltAndFinalize = "HkdfSaltAndFinalize"
	BcryptHkdfPrkAndFinalize  = "HkdfPrkAndFinalize"

	// BCryptSetProperty strings
	BcryptInitializationVector = "IV"

	// Property Strings
	BcryptChainModeNa  = "ChainingModeN/A"
	BcryptChainModeCbc = "ChainingModeCBC"
	BcryptChainModeEcb = "ChainingModeECB"
	BcryptChainModeCfb = "ChainingModeCFB"
	BcryptChainModeCcm = "ChainingModeCCM"
	BcryptChainModeGcm = "ChainingModeGCM"

	// Supported RSA Padding Types
	BcryptSupportedPadRouter   = 0x00000001
	BcryptSupportedPadPkcs1Enc = 0x00000002
	BcryptSupportedPadPkcs1Sig = 0x00000004
	BcryptSupportedPadOaep     = 0x00000008
	BcryptSupportedPadPss      = 0x00000010

	//
	//      BCrypt Flags
	//
	BcryptProvDispatch = 0x00000001 // BCryptOpenAlgorithmProvider
	BcryptBlockPadding = 0x00000001 // BCryptEncrypt/Decrypt

	// RSA padding schemes
	BcryptPadNone                 = 0x00000001
	BcryptPadPkcs1                = 0x00000002 // BCryptEncrypt/Decrypt BCryptSignHash/VerifySignature
	BcryptPadOaep                 = 0x00000004 // BCryptEncrypt/Decrypt
	BcryptPadPss                  = 0x00000008 // BCryptSignHash/VerifySignature
	BcryptPadPkcs1OptionalHashOid = 0x00000010 // BCryptVerifySignature
	BcryptbufferVersion           = 0

	//
	// Structures used to represent key blobs.
	//
	BcryptPublicKeyBlob  = "PUBLICBLOB"
	BcryptPrivateKeyBlob = "PRIVATEBLOB"

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
	BcryptRsapublicBlob       = "RSAPUBLICBLOB"
	BcryptRsaprivateBlob      = "RSAPRIVATEBLOB"
	LegacyRsapublicBlob       = "CAPIPUBLICBLOB"
	LegacyRsaprivateBlob      = "CAPIPRIVATEBLOB"
	BcryptRsapublicMagic      = 0x31415352 // RSA1
	BcryptRsaprivateMagic     = 0x32415352 // RSA2
	BcryptRsafullprivateBlob  = "RSAFULLPRIVATEBLOB"
	BcryptRsafullprivateMagic = 0x33415352 // RSA3

	//Properties of secret agreement algorithms
	BcryptGlobalParameters = "SecretAgreementParam"
	BcryptPrivateKey       = "PrivKeyVal"

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
	BcryptEccpublicBlob            = "ECCPUBLICBLOB"
	BcryptEccprivateBlob           = "ECCPRIVATEBLOB"
	BcryptEccfullpublicBlob        = "ECCFULLPUBLICBLOB"
	BcryptEccfullprivateBlob       = "ECCFULLPRIVATEBLOB"
	SslEccpublicBlob               = "SSLECCPUBLICBLOB"
	BcryptEcdhPublicP256Magic      = 0x314B4345 // ECK1
	BcryptEcdhPrivateP256Magic     = 0x324B4345 // ECK2
	BcryptEcdhPublicP384Magic      = 0x334B4345 // ECK3
	BcryptEcdhPrivateP384Magic     = 0x344B4345 // ECK4
	BcryptEcdhPublicP521Magic      = 0x354B4345 // ECK5
	BcryptEcdhPrivateP521Magic     = 0x364B4345 // ECK6
	BcryptEcdhPublicGenericMagic   = 0x504B4345 // ECKP
	BcryptEcdhPrivateGenericMagic  = 0x564B4345 // ECKV
	BcryptEcdsaPublicP256Magic     = 0x31534345 // ECS1
	BcryptEcdsaPrivateP256Magic    = 0x32534345 // ECS2
	BcryptEcdsaPublicP384Magic     = 0x33534345 // ECS3
	BcryptEcdsaPrivateP384Magic    = 0x34534345 // ECS4
	BcryptEcdsaPublicP521Magic     = 0x35534345 // ECS5
	BcryptEcdsaPrivateP521Magic    = 0x36534345 // ECS6
	BcryptEcdsaPublicGenericMagic  = 0x50444345 // ECDP
	BcryptEcdsaPrivateGenericMagic = 0x56444345 // ECDV

	//ECC Full versions
	BcryptEccFullkeyBlobV1 = 0x1

	// The BCRYPT_DH_PUBLIC_BLOB and BCRYPT_DH_PRIVATE_BLOB blob types are used
	// to transport plaintext DH keys. These blob types will be supported by
	// all DH primitive providers.
	BcryptDhPublicBlob   = "DHPUBLICBLOB"
	BcryptDhPrivateBlob  = "DHPRIVATEBLOB"
	LegacyDhPublicBlob   = "CAPIDHPUBLICBLOB"
	LegacyDhPrivateBlob  = "CAPIDHPRIVATEBLOB"
	BcryptDhPublicMagic  = 0x42504844 // DHPB
	BcryptDhPrivateMagic = 0x56504844 // DHPV

	// Property Strings for DH
	BcryptDhParameters      = "DHParameters"
	BcryptDhParametersMagic = 0x4d504844 // DHPM

	// The BCRYPT_DSA_PUBLIC_BLOB and BCRYPT_DSA_PRIVATE_BLOB blob types are used
	// to transport plaintext DSA keys. These blob types will be supported by
	// all DSA primitive providers.
	BcryptDsaPublicBlob       = "DSAPUBLICBLOB"
	BcryptDsaPrivateBlob      = "DSAPRIVATEBLOB"
	LegacyDsaPublicBlob       = "CAPIDSAPUBLICBLOB"
	LegacyDsaPrivateBlob      = "CAPIDSAPRIVATEBLOB"
	LegacyDsaV2PublicBlob     = "V2CAPIDSAPUBLICBLOB"
	LegacyDsaV2PrivateBlob    = "V2CAPIDSAPRIVATEBLOB"
	BcryptDsaPublicMagic      = 0x42505344 // DSPB
	BcryptDsaPrivateMagic     = 0x56505344 // DSPV
	BcryptDsaPublicMagicV2    = 0x32425044 // DPB2
	BcryptDsaPrivateMagicV2   = 0x32565044 // DPV2
	BcryptKeyDataBlobMagic    = 0x4d42444b // Key Data Blob Magic (KDBM)
	BcryptKeyDataBlobVersion1 = 0x1

	// Property Strings for DSA
	BcryptDsaParameters        = "DSAParameters"
	BcryptDsaParametersMagic   = 0x4d505344 // DSPM
	BcryptDsaParametersMagicV2 = 0x324d5044 // DPM2

	// Property Strings for ECC
	BcryptEccParameters      = "ECCParameters"
	BcryptEccCurveName       = "ECCCurveName"
	BcryptEccCurveNameList   = "ECCCurveNameList"
	BcryptEccParametersMagic = 0x50434345 // ECCP

	//
	// ECC Curve Names
	//
	BcryptEccCurveBrainpoolp160r1 = "brainpoolP160r1"
	BcryptEccCurveBrainpoolp160t1 = "brainpoolP160t1"
	BcryptEccCurveBrainpoolp192r1 = "brainpoolP192r1"
	BcryptEccCurveBrainpoolp192t1 = "brainpoolP192t1"
	BcryptEccCurveBrainpoolp224r1 = "brainpoolP224r1"
	BcryptEccCurveBrainpoolp224t1 = "brainpoolP224t1"
	BcryptEccCurveBrainpoolp256r1 = "brainpoolP256r1"
	BcryptEccCurveBrainpoolp256t1 = "brainpoolP256t1"
	BcryptEccCurveBrainpoolp320r1 = "brainpoolP320r1"
	BcryptEccCurveBrainpoolp320t1 = "brainpoolP320t1"
	BcryptEccCurveBrainpoolp384r1 = "brainpoolP384r1"
	BcryptEccCurveBrainpoolp384t1 = "brainpoolP384t1"
	BcryptEccCurveBrainpoolp512r1 = "brainpoolP512r1"
	BcryptEccCurveBrainpoolp512t1 = "brainpoolP512t1"
	BcryptEccCurve25519           = "curve25519"
	BcryptEccCurveEc192wapi       = "ec192wapi"
	BcryptEccCurveNistp192        = "nistP192"
	BcryptEccCurveNistp224        = "nistP224"
	BcryptEccCurveNistp256        = "nistP256"
	BcryptEccCurveNistp384        = "nistP384"
	BcryptEccCurveNistp521        = "nistP521"
	BcryptEccCurveNumsp256t1      = "numsP256t1"
	BcryptEccCurveNumsp384t1      = "numsP384t1"
	BcryptEccCurveNumsp512t1      = "numsP512t1"
	BcryptEccCurveSecp160k1       = "secP160k1"
	BcryptEccCurveSecp160r1       = "secP160r1"
	BcryptEccCurveSecp160r2       = "secP160r2"
	BcryptEccCurveSecp192k1       = "secP192k1"
	BcryptEccCurveSecp192r1       = "secP192r1"
	BcryptEccCurveSecp224k1       = "secP224k1"
	BcryptEccCurveSecp224r1       = "secP224r1"
	BcryptEccCurveSecp256k1       = "secP256k1"
	BcryptEccCurveSecp256r1       = "secP256r1"
	BcryptEccCurveSecp384r1       = "secP384r1"
	BcryptEccCurveSecp521r1       = "secP521r1"
	BcryptEccCurveWtls7           = "wtls7"
	BcryptEccCurveWtls9           = "wtls9"
	BcryptEccCurveWtls12          = "wtls12"
	BcryptEccCurveX962p192v1      = "x962P192v1"
	BcryptEccCurveX962p192v2      = "x962P192v2"
	BcryptEccCurveX962p192v3      = "x962P192v3"
	BcryptEccCurveX962p239v1      = "x962P239v1"
	BcryptEccCurveX962p239v2      = "x962P239v2"
	BcryptEccCurveX962p239v3      = "x962P239v3"
	BcryptEccCurveX962p256v1      = "x962P256v1"

	//
	// Microsoft built-in providers.
	//
	MsPrimitiveProvider      = "Microsoft Primitive Provider"
	MsPlatformCryptoProvider = "Microsoft Platform Crypto Provider"

	//
	// Common algorithm identifiers.
	//
	BcryptRsaAlgorithm             = "RSA"
	BcryptRsaSignAlgorithm         = "RSA_SIGN"
	BcryptDhAlgorithm              = "DH"
	BcryptDsaAlgorithm             = "DSA"
	BcryptRc2Algorithm             = "RC2"
	BcryptRc4Algorithm             = "RC4"
	BcryptAesAlgorithm             = "AES"
	BcryptDesAlgorithm             = "DES"
	BcryptDesxAlgorithm            = "DESX"
	Bcrypt3desAlgorithm            = "3DES"
	Bcrypt3des112Algorithm         = "3DES_112"
	BcryptMd2Algorithm             = "MD2"
	BcryptMd4Algorithm             = "MD4"
	BcryptMd5Algorithm             = "MD5"
	BcryptSha1Algorithm            = "SHA1"
	BcryptSha256Algorithm          = "SHA256"
	BcryptSha384Algorithm          = "SHA384"
	BcryptSha512Algorithm          = "SHA512"
	BcryptAesGmacAlgorithm         = "AES-GMAC"
	BcryptAesCmacAlgorithm         = "AES-CMAC"
	BcryptEcdsaP256Algorithm       = "ECDSA_P256"
	BcryptEcdsaP384Algorithm       = "ECDSA_P384"
	BcryptEcdsaP521Algorithm       = "ECDSA_P521"
	BcryptEcdhP256Algorithm        = "ECDH_P256"
	BcryptEcdhP384Algorithm        = "ECDH_P384"
	BcryptEcdhP521Algorithm        = "ECDH_P521"
	BcryptRngAlgorithm             = "RNG"
	BcryptRngFips186DsaAlgorithm   = "FIPS186DSARNG"
	BcryptRngDualEcAlgorithm       = "DUALECRNG"
	BcryptSp800108CtrHmacAlgorithm = "SP800_108_CTR_HMAC"
	BcryptSp80056aConcatAlgorithm  = "SP800_56A_CONCAT"
	BcryptPbkdf2Algorithm          = "PBKDF2"
	BcryptCapiKdfAlgorithm         = "CAPI_KDF"
	BcryptTls11KdfAlgorithm        = "TLS1_1_KDF"
	BcryptTls12KdfAlgorithm        = "TLS1_2_KDF"
	BcryptEcdsaAlgorithm           = "ECDSA"
	BcryptEcdhAlgorithm            = "ECDH"
	BcryptXtsAesAlgorithm          = "XTS-AES"
	BcryptHkdfAlgorithm            = "HKDF"

	//
	// Interfaces
	//
	BcryptCipherInterface               = 0x00000001
	BcryptHashInterface                 = 0x00000002
	BcryptAsymmetricEncryptionInterface = 0x00000003
	BcryptSecretAgreementInterface      = 0x00000004
	BcryptSignatureInterface            = 0x00000005
	BcryptRngInterface                  = 0x00000006
	BcryptKeyDerivationInterface        = 0x00000007

	//
	// Primitive algorithm provider functions.
	//
	BcryptAlgHandleHmacFlag = 0x00000008
	BcryptHashReusableFlag  = 0x00000020
	BcryptCapiAesFlag       = 0x00000010
	BcryptMultiFlag         = 0x00000040

	//
	// The TLS_CBC_HMAC_VERIFY flag provides a side-channel safe way of verifying TLS data records
	// from the CBC-HMAC cipher suites. See RFC 5246 section 6.2.3.2.
	// This flag is used in BCryptOpenAlgorithmProvider and in BCryptHashData.
	// For BCryptOpenAlgorithmProvider it ensures that you get a provider that supports this feature.
	// For BCryptHashData is changes the functionality.
	// The Input buffer now contains the whole TLS data record, consisting of the plaintext,
	// followed by the MAC value, followed by the padding, followed by the padding_length.
	// The function will compute the HMAC over the data already hashed plus the plaintext,
	// compare it to the MAC value, and verify that the padding is correct.
	// If all works out, it returns a success value; if anything fails it returns an error.
	// What makes this special is that the code path or the memory access pattern used to
	// do this verification does not depend on padding_length to stop attacks on the CBC encryption
	// that was used to decrypt this data.
	// This flag is only useful for TLS implementations, other callers should not use it.
	// This flag is only valid for HMAC-SHA1, HMAC-SHA256, and HMAC-SHA384.
	// This flag implies the BCRYPT_HASH_REUSABLE_FLAG.
	//
	// This flag is available staring in Windows 10 19H1, but we define it for all
	// NTDDI values to allow applications to dynamically test wethere the OS supports the
	// feature, and adjust accordingly.
	//
	BcryptTlsCbcHmacVerifyFlag = 0x00000004

	//
	// The BUFFERS_LOCKED flag used in BCryptEncrypt/BCryptDecrypt signals that
	// the pbInput and pbOutput buffers have been locked (see MmProbeAndLockPages)
	// and CNG may not lock the buffers again.
	// This flag applies only to kernel mode, it is ignored in user mode.
	//
	BcryptBuffersLockedFlag = 0x00000040

	//
	// The EXTENDED_KEYSIZE flag extends the supported set of key sizes.
	//
	// The original design has a per-algorithm maximum key size, and
	// BCryptGenerateSymmetricKey truncates any longer input to the maximum key size for that
	// algorithm. Some callers depend on this feature and pass in large buffers.
	// This makes it impossible to silently extend the supported key size without breaking
	// backward compatibility.
	// This flag indicates that the extended key size support is requested.
	// It has the following consequences:
	// - BCryptGetProperty will report a new maximum key size for BCRYPT_KEY_LENGTHS.
	// - BCryptGenerateSymmetricKey will support the longer key sizes.
	// - BCryptGenerateSymmetricKey will no longer truncate keys that are too long, but return an error instead.
	//
	BcryptExtendedKeysize = 0x00000080

	//
	// ENABLE_INCOMPATIBLE_FIPS_CHECKS flag enables some FIPS 140-2-mandated checks that are incompatible
	// with the original algorithm.
	//
	// Starting in Redstone 1 (summer 2016 release of Win10) this flag has the following effect on the
	//  Microsoft default algorithm provider.
	// - BCryptGenerateSymmetricKey when generating an XTS-AES key with this flag specified and FIPS mode enabled
	//      will verify that the two halves of the key are not identical. If they are, an error is returned.
	//      This is actually incompatible with the NIST SP 800-38E and IEEE Std 1619-2007 definitions
	//      of XTS-AES. Rather than change the standard, NIST added this requirement in the FIPS 140-2
	//      implementation guidance.
	//      This check breaks existing usage of the algorithm, which is why we only perform the check when the
	//      caller explicitly asks for it.
	//      Use of this flag  for any algorithm other than XTS-AES generates an error.
	// Note that this flag is not supported for BCryptImportKey.
	//
	BcryptEnableIncompatibleFipsChecks = 0x00000100

	// AlgOperations flags for use with BCryptEnumAlgorithms()
	BcryptCipherOperation               = 0x00000001
	BcryptHashOperation                 = 0x00000002
	BcryptAsymmetricEncryptionOperation = 0x00000004
	BcryptSecretAgreementOperation      = 0x00000008
	BcryptSignatureOperation            = 0x00000010
	BcryptRngOperation                  = 0x00000020
	BcryptKeyDerivationOperation        = 0x00000040

	// Unused flags. Kept for backward compatibility.
	//   "Flags for use with BCryptGetProperty and BCryptSetProperty"
	BcryptPublicKeyFlag   = 0x00000001
	BcryptPrivateKeyFlag  = 0x00000002
	BcryptNoKeyValidation = 0x00000008

	//
	// Primitive random number generation.
	//
	// Flags to BCryptGenRandom
	// BCRYPT_RNG_USE_ENTROPY_IN_BUFFER is ignored in Win7 & later
	BcryptRngUseEntropyInBuffer = 0x00000001
	BcryptUseSystemPreferredRng = 0x00000002

	//
	// Operation types used in BCRYPT_MULTI_HASH_OPERATION structures
	//
	BcryptHashOperationHashData   = 1
	BcryptHashOperationFinishHash = 2

	//
	// Enum to specify type of multi-operation is passed to BCryptProcesMultiOperations
	//
	BcryptOperationTypeHash = 1 // structure type is BCRYPT_MULTI_HASH_OPERATION

	//
	// Others
	//
	BcryptHashInterfaceMajorversion2    = 2
	BcryptEccPrimeShortWeierstrassCurve = 0x1
	BcryptEccPrimeTwistedEdwardsCurve   = 0x2
	BcryptEccPrimeMontgomeryCurve       = 0x3
	BcryptNoCurveGenerationAlgId        = 0x0
	DsaHashAlgorithmSha1                = 0
	DsaHashAlgorithmSha256              = 1
	DsaHashAlgorithmSha512              = 2
	DsaFips1862                         = 0
	DsaFips1863                         = 1

	//////////////////////////////////////////////////////////////////////////////
	// CryptoConfig Definitions //////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////
	// Interface registration flags
	CryptMinDependencies = (0x00000001)
	CryptProcessIsolate  = (0x00010000) // User-mode only

	// Processor modes supported by a provider
	//
	// (Valid for BCryptQueryProviderRegistration and BCryptResolveProviders):
	//
	CryptUm = (0x00000001) // User mode only
	CryptKm = (0x00000002) // Kernel mode only
	CryptMm = (0x00000003) // Multi-mode: Must support BOTH UM and KM

	//
	// (Valid only for BCryptQueryProviderRegistration):
	//
	CryptAny = (0x00000004) // Wildcard: Either UM, or KM, or both

	// Write behavior flags
	CryptOverwrite = (0x00000001)

	// Configuration tables
	CryptLocal  = (0x00000001)
	CryptDomain = (0x00000002)

	// Context configuration flags
	CryptExclusive = (0x00000001)
	CryptOverride  = (0x00010000) // Enterprise table only

	// Resolution and enumeration flags
	CryptAllFunctions = (0x00000001)
	CryptAllProviders = (0x00000002)

	// Priority list positions
	CryptPriorityTop    = (0x00000000)
	CryptPriorityBottom = (0xFFFFFFFF)
)

//
// BCrypt structures.
//
type BcryptBuffer struct {
	CbBuffer   uint32 // Length of buffer, in bytes
	BufferType uint32 // Buffer type
	PvBuffer   []byte // Pointer to buffer
}
type BcryptBufferDesc struct {
	UlVersion uint32            // Version number
	CBuffers  uint32            // Number of buffers
	PBuffers  *BcryptBufferDesc // Pointer to array of buffers
}
type BcryptKeyLengthsStruct struct {
	DwMinLength uint32
	DwMaxLength uint32
	DwIncrement uint32
}
type BcryptOid struct {
	CbOID uint32
	PbOID []byte
}
type BcryptOidList struct {
	DwOIDCount uint32
	POIDs      *BcryptOid
}
type BcryptPkcs1PaddingInfo struct {
	PszAlgId []uint16
}
type BcryptPssPaddingInfo struct {
	PszAlgId []uint16
	CbSalt   uint32
}
type BcryptOaepPaddingInfo struct {
	PszAlgId []uint16
	PbLabel  []byte
	CbLabel  uint32
}
type BcryptAuthenticatedCipherModeInfo struct {
	CbSize        uint32
	DwInfoVersion uint32
	PbNonce       []byte
	CbNonce       uint32
	PbAuthData    []byte
	CbAuthData    uint32
	PbTag         []byte
	CbTag         uint32
	PbMacContext  []byte
	CbMacContext  uint32
	CbAAD         uint32
	CbData        uint64
	DwFlags       uint32
}
type BcryptKeyBlob struct {
	Magic uint32
}
type BcryptRsakeyBlob struct {
	Magic       uint32
	BitLength   uint32
	CbPublicExp uint32
	CbModulus   uint32
	CbPrime1    uint32
	CbPrime2    uint32
}
type BcryptEcckeyBlob struct {
	DwMagic uint32
	CbKey   uint32
}
type sslEcckeyBlob struct { //SSL ECC Public Blob Version
	DwCurveType uint32
	CbKey       uint32
}
type BcryptEccfullkeyBlob struct { //The full version contains the curve parameters as well as the public and potentially private exponent.
	DwMagic                uint32
	DwVersion              uint32 //Version of the structure
	DwCurveType            int    //Supported curve types.
	DwCurveGenerationAlgId int    //For X.592 verification purposes, if we include Seed we will need to include the algorithm ID.
	CbFieldLength          uint32 //Byte length of the fields P, A, B, X, Y.
	CbSubgroupOrder        uint32 //Byte length of the subgroup.
	CbCofactor             uint32 //Byte length of cofactor of G in E.
	CbSeed                 uint32 //Byte length of the seed used to generate the curve.
	//P[cbFieldLength]              Prime specifying the base field.
	//A[cbFieldLength]              Coefficient A of the equation y^2 = x^3 + A*x + B mod p
	//B[cbFieldLength]              Coefficient B of the equation y^2 = x^3 + A*x + B mod p
	//Gx[cbFieldLength]             X-coordinate of the base point.
	//Gy[cbFieldLength]             Y-coordinate of the base point.
	//n[cbSubgroupOrder]            Order of the group generated by G = (x,y)
	//h[cbCofactor]                 Cofactor of G in E.
	//S[cbSeed]                     Seed of the curve.
	//Qx[cbFieldLength]             X-coordinate of the public point.
	//Qy[cbFieldLength]             Y-coordinate of the public point.
	//d[cbSubgroupOrder]            Private key.  Not always present.
}
type BcryptDhKeyBlob struct {
	DwMagic uint32
	CbKey   uint32
}
type BcryptDhParameterHeader struct {
	CbLength    uint32
	DwMagic     uint32
	CbKeyLength uint32
}
type BcryptDsaKeyBlob struct {
	DwMagic uint32
	CbKey   uint32
	Count   [4]byte
	Seed    [20]byte
	Q       [20]byte
}
type BcryptDsaKeyBlobV2 struct {
	DwMagic         uint32
	CbKey           uint32
	HashAlgorithm   int
	StandardVersion int
	CbSeedLength    uint32
	CbGroupSize     uint32
	Count           [4]byte
}
type BcryptKeyDataBlobHeader struct {
	DwMagic   uint32
	DwVersion uint32
	CbKeyData uint32
}
type BcryptDsaParameterHeader struct {
	CbLength    uint32
	DwMagic     uint32
	CbKeyLength uint32
	Count       [4]byte
	Seed        [20]byte
	Q           [20]byte
}
type BcryptDsaParameterHeaderV2 struct {
	CbLength        uint32
	DwMagic         uint32
	CbKeyLength     uint32
	HashAlgorithm   int
	StandardVersion int
	CbSeedLength    uint32
	CbGroupSize     uint32
	Count           [4]byte
}
type BcryptEccCurveNames struct {
	DwEccCurveNames uint32
	PEccCurveNames  **uint16
}
type BcryptMultiHashOperation struct {
	IHash         uint32 // index of hash object
	HashOperation int    // operation to be performed
	PbBuffer      *byte  // data to be hashed, or result buffer (_Field_size_(cbBuffer))
	CbBuffer      uint32
}
type BcryptMultiObjectLengthStruct struct {
	CbPerObject  uint32
	CbPerElement uint32 // required size for N elements is (cbPerObject + N * cbPerElement)
}
type BcryptAlgorithmIdentifier struct {
	PszName *uint16
	DwClass uint32
	DwFlags uint32
}
type BcryptProviderName struct {
	PszProviderName *uint16
}
type BcryptInterfaceVersion struct {
	MajorVersion uint16
	MinorVersion uint16
}

//////////////////////////////////////////////////////////////////////////////////////
// NCrypt header content.
// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um\ncrypt.h
//////////////////////////////////////////////////////////////////////////////////////

const (

	//
	// Maximum length of Key name, in characters
	//
	NcryptMaxKeyNameLength = 512

	//
	// Maximum length of Algorithm name, in characters
	//
	NcryptMaxAlgIdLength = 512

	//
	// Microsoft built-in providers.
	//
	MsKeyStorageProvider          = "Microsoft Software Key Storage Provider"
	MsSmartCardKeyStorageProvider = "Microsoft Smart Card Key Storage Provider"
	MsPlatformKeyStorageProvider  = "Microsoft Platform Crypto Provider"
	MsNgcKeyStorageProvider       = "Microsoft Passport Key Storage Provider"

	//
	// Key name for sealing
	//
	TpmRsaSrkSealKey = "MICROSOFT_PCP_KSP_RSA_SEAL_KEY_3BD1C4BF-004E-4E2F-8A4D-0BF633DCB074"

	//
	// Common algorithm identifiers.
	//
	NcryptRsaAlgorithm             = BcryptRsaAlgorithm
	NcryptRsaSignAlgorithm         = BcryptRsaSignAlgorithm
	NcryptDhAlgorithm              = BcryptDhAlgorithm
	NcryptDsaAlgorithm             = BcryptDsaAlgorithm
	NcryptMd2Algorithm             = BcryptMd2Algorithm
	NcryptMd4Algorithm             = BcryptMd4Algorithm
	NcryptMd5Algorithm             = BcryptMd5Algorithm
	NcryptSha1Algorithm            = BcryptSha1Algorithm
	NcryptSha256Algorithm          = BcryptSha256Algorithm
	NcryptSha384Algorithm          = BcryptSha384Algorithm
	NcryptSha512Algorithm          = BcryptSha512Algorithm
	NcryptEcdsaP256Algorithm       = BcryptEcdsaP256Algorithm
	NcryptEcdsaP384Algorithm       = BcryptEcdsaP384Algorithm
	NcryptEcdsaP521Algorithm       = BcryptEcdsaP521Algorithm
	NcryptEcdhP256Algorithm        = BcryptEcdhP256Algorithm
	NcryptEcdhP384Algorithm        = BcryptEcdhP384Algorithm
	NcryptEcdhP521Algorithm        = BcryptEcdhP521Algorithm
	NcryptAesAlgorithm             = BcryptAesAlgorithm
	NcryptRc2Algorithm             = BcryptRc2Algorithm
	Ncrypt3desAlgorithm            = Bcrypt3desAlgorithm
	NcryptDesAlgorithm             = BcryptDesAlgorithm
	NcryptDesxAlgorithm            = BcryptDesxAlgorithm
	Ncrypt3des112Algorithm         = Bcrypt3des112Algorithm
	NcryptSp800108CtrHmacAlgorithm = BcryptSp800108CtrHmacAlgorithm
	NcryptSp80056aConcatAlgorithm  = BcryptSp80056aConcatAlgorithm
	NcryptPbkdf2Algorithm          = BcryptPbkdf2Algorithm
	NcryptCapiKdfAlgorithm         = BcryptCapiKdfAlgorithm
	NcryptEcdsaAlgorithm           = BcryptEcdsaAlgorithm
	NcryptKeyStorageAlgorithm      = "KEY_STORAGE"

	//
	// This algorithm is not supported by any BCrypt provider. This identifier is for creating
	// persistent stored HMAC keys in the TPM KSP.
	//
	NcryptHmacSha256Algorithm = "HMAC-SHA256"

	//
	// Interfaces
	//
	NcryptCipherInterface               = BcryptCipherInterface
	NcryptHashInterface                 = BcryptHashInterface
	NcryptAsymmetricEncryptionInterface = BcryptAsymmetricEncryptionInterface
	NcryptSecretAgreementInterface      = BcryptSecretAgreementInterface
	NcryptSignatureInterface            = BcryptSignatureInterface
	NcryptKeyDerivationInterface        = BcryptKeyDerivationInterface
	NcryptKeyStorageInterface           = 0x00010001
	NcryptSchannelInterface             = 0x00010002
	NcryptSchannelSignatureInterface    = 0x00010003
	NcryptKeyProtectionInterface        = 0x00010004

	//
	// algorithm groups.
	//
	NcryptRsaAlgorithmGroup   = NcryptRsaAlgorithm
	NcryptDhAlgorithmGroup    = NcryptDhAlgorithm
	NcryptDsaAlgorithmGroup   = NcryptDsaAlgorithm
	NcryptEcdsaAlgorithmGroup = "ECDSA"
	NcryptEcdhAlgorithmGroup  = "ECDH"
	NcryptAesAlgorithmGroup   = NcryptAesAlgorithm
	NcryptRc2AlgorithmGroup   = NcryptRc2Algorithm
	NcryptDesAlgorithmGroup   = "DES"
	NcryptKeyDerivationGroup  = "KEY_DERIVATION"

	//
	// NCrypt generic memory descriptors
	//
	NcryptbufferVersion                    = 0
	NcryptbufferEmpty                      = 0
	NcryptbufferData                       = 1
	NcryptbufferProtectionDescriptorString = 3 // The buffer contains a null-terminated Unicode string that contains the Protection Descriptor.
	NcryptbufferProtectionFlags            = 4 // DWORD flags to be passed to NCryptCreateProtectionDescriptor function.
	NcryptbufferSslClientRandom            = 20
	NcryptbufferSslServerRandom            = 21
	NcryptbufferSslHighestVersion          = 22
	NcryptbufferSslClearKey                = 23
	NcryptbufferSslKeyArgData              = 24
	NcryptbufferSslSessionHash             = 25
	NcryptbufferPkcsOid                    = 40
	NcryptbufferPkcsAlgOid                 = 41
	NcryptbufferPkcsAlgParam               = 42
	NcryptbufferPkcsAlgId                  = 43
	NcryptbufferPkcsAttrs                  = 44
	NcryptbufferPkcsKeyName                = 45
	NcryptbufferPkcsSecret                 = 46
	NcryptbufferCertBlob                   = 47
	//for threshold key attestation
	NcryptbufferClaimIdbindingNonce                = 48
	NcryptbufferClaimKeyattestationNonce           = 49
	NcryptbufferKeyPropertyFlags                   = 50
	NcryptbufferAttestationstatementBlob           = 51
	NcryptbufferAttestationClaimType               = 52
	NcryptbufferAttestationClaimChallengeRequired  = 53
	NcryptbufferVsmKeyAttestationClaimRestrictions = 54
	//for generic ecc
	NcryptbufferEccCurveName  = 60
	NcryptbufferEccParameters = 61
	//for TPM seal
	NcryptbufferTpmSealPassword       = 70
	NcryptbufferTpmSealPolicyinfo     = 71
	NcryptbufferTpmSealTicket         = 72
	NcryptbufferTpmSealNoDaProtection = 73
	// for TPM platform attestation statements
	NcryptbufferTpmPlatformClaimPcrMask      = 80
	NcryptbufferTpmPlatformClaimNonce        = 81
	NcryptbufferTpmPlatformClaimStaticCreate = 82

	//
	// The following flags are used with NCRYPT_CIPHER_PADDING_INFO
	//
	NcryptCipherNoPaddingFlag    = 0x00000000
	NcryptCipherBlockPaddingFlag = 0x00000001
	NcryptCipherOtherPaddingFlag = 0x00000002
	NcryptPlatformAttestMagic    = 0x44504150 // 'PAPD'
	NcryptKeyAttestMagic         = 0x4450414b // 'KAPD'

	//
	// key attestation claim type
	//
	NcryptClaimAuthorityOnly              = 0x00000001
	NcryptClaimSubjectOnly                = 0x00000002
	NcryptClaimWebAuthSubjectOnly         = 0x00000102
	NcryptClaimAuthorityAndSubject        = 0x00000003
	NcryptClaimVsmKeyAttestationStatement = 0x00000004
	NcryptClaimUnknown                    = 0x00001000
	NcryptClaimPlatform                   = 0x00010000
	// NCryptCreateClaim claim types, flags and buffer types
	NcryptIsolatedKeyFlagCreatedInIsolation           = 0x00000001 // if set, this key was generated in isolation, not imported
	NcryptIsolatedKeyFlagImportOnly                   = 0x00000002 // if set, this key can only be used for importing other keys
	NcryptIsolatedKeyAttestedAttributesV0             = 0
	NcryptIsolatedKeyAttestedAttributesCurrentVersion = NcryptIsolatedKeyAttestedAttributesV0
	NcryptVsmKeyAttestationStatementV0                = 0
	NcryptVsmKeyAttestationStatementCurrentVersion    = NcryptVsmKeyAttestationStatementV0
	// Buffer contents for NCryptVerifyClaim (for buffer type NCRYPTBUFFER_ISOLATED_KEY_ATTESTATION_CLAIM_RESTRICTIONS)
	NcryptVsmKeyAttestationClaimRestrictionsV0             = 0
	NcryptVsmKeyAttestationClaimRestrictionsCurrentVersion = NcryptVsmKeyAttestationClaimRestrictionsV0
	// Structures to assist with importation of isolated keys
	NcryptExportedIsolatedKeyHeaderV0                   = 0
	NcryptExportedIsolatedKeyHeaderCurrentVersion       = NcryptExportedIsolatedKeyHeaderV0
	NcryptTpmPlatformAttestationStatementV0             = 0
	NcryptTpmPlatformAttestationStatementCurrentVersion = NcryptTpmPlatformAttestationStatementV0

	//
	// NCrypt API Flags
	//
	NcryptNoPaddingFlag              = 0x00000001 // NCryptEncrypt/Decrypt
	NcryptPadPkcs1Flag               = 0x00000002 // NCryptEncrypt/Decrypt NCryptSignHash/VerifySignature
	NcryptPadOaepFlag                = 0x00000004 // BCryptEncrypt/Decrypt
	NcryptPadPssFlag                 = 0x00000008 // BCryptSignHash/VerifySignature
	NcryptPadCipherFlag              = 0x00000010 // NCryptEncrypt/Decrypt
	NcryptAttestationFlag            = 0x00000020 // NCryptDecrypt for key attestation
	NcryptSealingFlag                = 0x00000100 // NCryptEncrypt/Decrypt for sealing
	NcryptRegisterNotifyFlag         = 0x00000001 // NCryptNotifyChangeKey
	NcryptUnregisterNotifyFlag       = 0x00000002 // NCryptNotifyChangeKey
	NcryptNoKeyValidation            = BcryptNoKeyValidation
	NcryptMachineKeyFlag             = 0x00000020 // same as CAPI CRYPT_MACHINE_KEYSET
	NcryptSilentFlag                 = 0x00000040 // same as CAPI CRYPT_SILENT
	NcryptOverwriteKeyFlag           = 0x00000080
	NcryptWriteKeyToLegacyStoreFlag  = 0x00000200
	NcryptDoNotFinalizeFlag          = 0x00000400
	NcryptExportLegacyFlag           = 0x00000800
	NcryptIgnoreDeviceStateFlag      = 0x00001000 // NCryptOpenStorageProvider
	NcryptTreatNistAsGenericEccFlag  = 0x00002000
	NcryptNoCachedPassword           = 0x00004000
	NcryptProtectToLocalSystem       = 0x00008000
	NcryptPersistOnlyFlag            = 0x40000000
	NcryptPersistFlag                = 0x80000000
	NcryptPreferVirtualIsolationFlag = 0x00010000 // NCryptCreatePersistedKey NCryptImportKey
	NcryptUseVirtualIsolationFlag    = 0x00020000 // NCryptCreatePersistedKey NCryptImportKey
	NcryptUsePerBootKeyFlag          = 0x00040000 // NCryptCreatePersistedKey NCryptImportKey
	// NCryptOpenStorageProvider flags
	/*
		NcryptSilentFlag            = 0x00000040 // same as CAPI CRYPT_SILENT
		NcryptIgnoreDeviceStateFlag = 0x00001000 // NCryptOpenStorageProvider
	*/
	// AlgOperations flags for use with NCryptEnumAlgorithms()
	NcryptCipherOperation               = BcryptCipherOperation
	NcryptHashOperation                 = BcryptHashOperation
	NcryptAsymmetricEncryptionOperation = BcryptAsymmetricEncryptionOperation
	NcryptSecretAgreementOperation      = BcryptSecretAgreementOperation
	NcryptSignatureOperation            = BcryptSignatureOperation
	NcryptRngOperation                  = BcryptRngOperation
	NcryptKeyDerivationOperation        = BcryptKeyDerivationOperation
	/*
		// NCryptEnumKeys flags
		NcryptMachineKeyFlag = 0x00000020
		// NCryptOpenKey flags
		NcryptMachineKeyFlag   = 0x00000020
		NcryptSilentFlag       = 0x00000040
		NcryptAuthorityKeyFlag = 0x00000100
		// NCryptCreatePersistedKey flags
		NcryptMachineKeyFlag   = 0x00000020
		NcryptOverwriteKeyFlag = 0x00000080
	*/
	// Standard property names.
	NcryptNameProperty                 = "Name"
	NcryptUniqueNameProperty           = "Unique Name"
	NcryptAlgorithmProperty            = "Algorithm Name"
	NcryptLengthProperty               = "Length"
	NcryptLengthsProperty              = "Lengths"
	NcryptBlockLengthProperty          = "Block Length"
	NcryptPublicLengthProperty         = BcryptPublicKeyLength
	NcryptSignatureLengthProperty      = BcryptSignatureLength
	NcryptChainingModeProperty         = "Chaining Mode"
	NcryptAuthTagLength                = "AuthTagLength"
	NcryptUiPolicyProperty             = "UI Policy"
	NcryptExportPolicyProperty         = "Export Policy"
	NcryptWindowHandleProperty         = "HWND Handle"
	NcryptUseContextProperty           = "Use Context"
	NcryptImplTypeProperty             = "Impl Type"
	NcryptKeyUsageProperty             = "Key Usage"
	NcryptKeyTypeProperty              = "Key Type"
	NcryptVersionProperty              = "Version"
	NcryptSecurityDescrSupportProperty = "Security Descr Support"
	NcryptSecurityDescrProperty        = "Security Descr"
	NcryptUseCountEnabledProperty      = "Enabled Use Count"
	NcryptUseCountProperty             = "Use Count"
	NcryptLastModifiedProperty         = "Modified"
	NcryptMaxNameLengthProperty        = "Max Name Length"
	NcryptAlgorithmGroupProperty       = "Algorithm Group"
	NcryptDhParametersProperty         = BcryptDhParameters
	NcryptEccParametersProperty        = BcryptEccParameters
	NcryptEccCurveNameProperty         = BcryptEccCurveName
	NcryptEccCurveNameListProperty     = BcryptEccCurveNameList
	NcryptUseVirtualIsolationProperty  = "Virtual Iso"
	NcryptUsePerBootKeyProperty        = "Per Boot Key"
	NcryptProviderHandleProperty       = "Provider Handle"
	NcryptPinProperty                  = "SmartCardPin"
	NcryptReaderProperty               = "SmartCardReader"
	NcryptSmartcardGuidProperty        = "SmartCardGuid"
	NcryptCertificateProperty          = "SmartCardKeyCertificate"
	NcryptPinPromptProperty            = "SmartCardPinPrompt"
	NcryptUserCertstoreProperty        = "SmartCardUserCertStore"
	NcryptRootCertstoreProperty        = "SmartcardRootCertStore"
	NcryptSecurePinProperty            = "SmartCardSecurePin"
	NcryptAssociatedEcdhKey            = "SmartCardAssociatedECDHKey"
	NcryptScardPinId                   = "SmartCardPinId"
	NcryptScardPinInfo                 = "SmartCardPinInfo"
	NcryptReaderIconProperty           = "SmartCardReaderIcon"
	NcryptKdfSecretValue               = "KDFKeySecret"
	NcryptDismissUiTimeoutSecProperty  = "SmartCardDismissUITimeoutSeconds"
	//
	// Additional property strings specific for the Platform Crypto Provider
	//
	NcryptPcpPlatformTypeProperty                 = "PCP_PLATFORM_TYPE"
	NcryptPcpProviderVersionProperty              = "PCP_PROVIDER_VERSION"
	NcryptPcpEkpubProperty                        = "PCP_EKPUB"
	NcryptPcpEkcertProperty                       = "PCP_EKCERT"
	NcryptPcpEknvcertProperty                     = "PCP_EKNVCERT"
	NcryptPcpRsaEkpubProperty                     = "PCP_RSA_EKPUB"
	NcryptPcpRsaEkcertProperty                    = "PCP_RSA_EKCERT"
	NcryptPcpRsaEknvcertProperty                  = "PCP_RSA_EKNVCERT"
	NcryptPcpEccEkpubProperty                     = "PCP_ECC_EKPUB"
	NcryptPcpEccEkcertProperty                    = "PCP_ECC_EKCERT"
	NcryptPcpEccEknvcertProperty                  = "PCP_ECC_EKNVCERT"
	NcryptPcpSrkpubProperty                       = "PCP_SRKPUB"
	NcryptPcpPcrtableProperty                     = "PCP_PCRTABLE"
	NcryptPcpChangepasswordProperty               = "PCP_CHANGEPASSWORD"
	NcryptPcpPasswordRequiredProperty             = "PCP_PASSWORD_REQUIRED"
	NcryptPcpUsageauthProperty                    = "PCP_USAGEAUTH"
	NcryptPcpMigrationpasswordProperty            = "PCP_MIGRATIONPASSWORD"
	NcryptPcpExportAllowedProperty                = "PCP_EXPORT_ALLOWED"
	NcryptPcpStorageparentProperty                = "PCP_STORAGEPARENT"
	NcryptPcpProviderhandleProperty               = "PCP_PROVIDERMHANDLE"
	NcryptPcpPlatformhandleProperty               = "PCP_PLATFORMHANDLE"
	NcryptPcpPlatformBindingPcrmaskProperty       = "PCP_PLATFORM_BINDING_PCRMASK"
	NcryptPcpPlatformBindingPcrdigestlistProperty = "PCP_PLATFORM_BINDING_PCRDIGESTLIST"
	NcryptPcpPlatformBindingPcrdigestProperty     = "PCP_PLATFORM_BINDING_PCRDIGEST"
	NcryptPcpKeyUsagePolicyProperty               = "PCP_KEY_USAGE_POLICY"
	NcryptPcpRsaSchemeProperty                    = "PCP_RSA_SCHEME"
	NcryptPcpRsaSchemeHashAlgProperty             = "PCP_RSA_SCHEME_HASH_ALG"
	NcryptPcpTpm12IdbindingProperty               = "PCP_TPM12_IDBINDING"
	NcryptPcpTpm12IdbindingDynamicProperty        = "PCP_TPM12_IDBINDING_DYNAMIC"
	NcryptPcpTpm12IdactivationProperty            = "PCP_TPM12_IDACTIVATION"
	NcryptPcpKeyattestationProperty               = "PCP_TPM12_KEYATTESTATION"
	NcryptPcpAlternateKeyStorageLocationProperty  = "PCP_ALTERNATE_KEY_STORAGE_LOCATION"
	NcryptPcpTpmIfxRsaKeygenProhibitedProperty    = "PCP_TPM_IFX_RSA_KEYGEN_PROHIBITED"
	NcryptPcpTpmIfxRsaKeygenVulnerabilityProperty = "PCP_TPM_IFX_RSA_KEYGEN_VULNERABILITY"
	NcryptPcpHmacAuthPolicyref                    = "PCP_HMAC_AUTH_POLICYREF"
	NcryptPcpHmacAuthPolicyinfo                   = "PCP_HMAC_AUTH_POLICYINFO"
	NcryptPcpHmacAuthNonce                        = "PCP_HMAC_AUTH_NONCE"
	NcryptPcpHmacAuthSignature                    = "PCP_HMAC_AUTH_SIGNATURE"
	NcryptPcpHmacAuthTicket                       = "PCP_HMAC_AUTH_TICKET"
	NcryptPcpNoDaProtectionProperty               = "PCP_NO_DA_PROTECTION"
	NcryptPcpTpmManufacturerIdProperty            = "PCP_TPM_MANUFACTURER_ID"
	NcryptPcpTpmFwVersionProperty                 = "PCP_TPM_FW_VERSION"
	NcryptPcpTpm2bnameProperty                    = "PCP_TPM2BNAME"
	NcryptPcpTpmVersionProperty                   = "PCP_TPM_VERSION"
	NcryptPcpRawPolicydigestProperty              = "PCP_RAW_POLICYDIGEST"
	NcryptPcpKeyCreationhashProperty              = "PCP_KEY_CREATIONHASH"
	NcryptPcpKeyCreationticketProperty            = "PCP_KEY_CREATIONTICKET"
	NcryptPcpSessionidProperty                    = "PCP_SESSIONID"
	NcryptPcpPssSaltSizeProperty                  = "PSS Salt Size"
	// TPM RSAPSS Salt size types
	NcryptTpmPssSaltSizeUnknown  = 0x00000000
	NcryptTpmPssSaltSizeMaximum  = 0x00000001 // Pre-TPM Spec-1.16: Max allowed salt size
	NcryptTpmPssSaltSizeHashsize = 0x00000002 // Post-1.16: PSS salt = hashLen
	// TPM NCryptSignHash Flag
	NcryptTpmPadPssIgnoreSalt = 0x00000020 // NCryptSignHash

	//
	// NCRYPT_PCP_TPM_IFX_RSA_KEYGEN_VULNERABILITY_PROPERTY values
	//
	IfxRsaKeygenVulNotAffected    = 0
	IfxRsaKeygenVulAffectedLevel1 = 1
	IfxRsaKeygenVulAffectedLevel2 = 2

	//
	// BCRYPT_PCP_KEY_USAGE_POLICY values
	//
	NcryptTpm12Provider          = (0x00010000)
	NcryptPcpSignatureKey        = (0x00000001)
	NcryptPcpEncryptionKey       = (0x00000002)
	NcryptPcpGenericKey          = (NcryptPcpSignatureKey | NcryptPcpEncryptionKey)
	NcryptPcpStorageKey          = (0x00000004)
	NcryptPcpIdentityKey         = (0x00000008)
	NcryptPcpHmacverificationKey = (0x00000010)

	//
	// Additional property strings specific for the Smart Card Key Storage Provider
	//
	NcryptScardNgcKeyName                    = "SmartCardNgcKeyName"
	NcryptPcpPlatformBindingPcralgidProperty = "PCP_PLATFORM_BINDING_PCRALGID"

	//
	// Used to set IV for block ciphers, before calling NCryptEncrypt/NCryptDecrypt
	//
	NcryptInitializationVector = BcryptInitializationVector

	NcryptChangepasswordProperty              = NcryptPcpChangepasswordProperty
	NcryptAlternateKeyStorageLocationProperty = NcryptPcpAlternateKeyStorageLocationProperty
	NcryptKeyAccessPolicyProperty             = "Key Access Policy"

	// Maximum length of property name (in characters)
	NcryptMaxPropertyName = 64

	// Maximum length of property data (in bytes)
	NcryptMaxPropertyData = 0x100000

	// NCRYPT_EXPORT_POLICY_PROPERTY property flags.
	NcryptAllowExportFlag             = 0x00000001
	NcryptAllowPlaintextExportFlag    = 0x00000002
	NcryptAllowArchivingFlag          = 0x00000004
	NcryptAllowPlaintextArchivingFlag = 0x00000008

	// NCRYPT_IMPL_TYPE_PROPERTY property flags.
	NcryptImplHardwareFlag         = 0x00000001
	NcryptImplSoftwareFlag         = 0x00000002
	NcryptImplRemovableFlag        = 0x00000008
	NcryptImplHardwareRngFlag      = 0x00000010
	NcryptImplVirtualIsolationFlag = 0x00000020

	// NCRYPT_KEY_USAGE_PROPERTY property flags.
	NcryptAllowDecryptFlag      = 0x00000001
	NcryptAllowSigningFlag      = 0x00000002
	NcryptAllowKeyAgreementFlag = 0x00000004
	NcryptAllowKeyImportFlag    = 0x00000008
	NcryptAllowAllUsages        = 0x00ffffff

	// NCRYPT_UI_POLICY_PROPERTY property flags and structure
	NcryptUiProtectKeyFlag               = 0x00000001
	NcryptUiForceHighProtectionFlag      = 0x00000002
	NcryptUiFingerprintProtectionFlag    = 0x00000004
	NcryptUiAppcontainerAccessMediumFlag = 0x00000008

	//
	// Pin Cache Provider Properties
	//
	NcryptPinCacheFreeApplicationTicketProperty = "PinCacheFreeApplicationTicket"
	NcryptPinCacheFlagsProperty                 = "PinCacheFlags"
	// The NCRYPT_PIN_CACHE_FLAGS_PROPERTY property is a DWORD value that can be set from a trusted process. The
	// following flags can be set.
	NcryptPinCacheDisableDplFlag = 0x00000001

	//
	// Pin Cache Key Properties
	//
	NcryptPinCacheApplicationTicketProperty = "PinCacheApplicationTicket"
	NcryptPinCacheApplicationImageProperty  = "PinCacheApplicationImage"
	NcryptPinCacheApplicationStatusProperty = "PinCacheApplicationStatus"
	NcryptPinCachePinProperty               = "PinCachePin"
	NcryptPinCacheIsGestureRequiredProperty = "PinCacheIsGestureRequired"
	NcryptPinCacheRequireGestureFlag        = 0x00000001
	// The NCRYPT_PIN_CACHE_PIN_PROPERTY and NCRYPT_PIN_CACHE_APPLICATION_TICKET_PROPERTY properties
	// return a 32 byte random unique ID encoded as a null terminated base64 Unicode string. The string length
	// is 32 * 4/3 + 1 characters = 45 characters, 90 bytes
	NcryptPinCachePinByteLength               = 90
	NcryptPinCacheApplicationTicketByteLength = 90
	NcryptPinCacheClearProperty               = "PinCacheClear"
	// The NCRYPT_PIN_CACHE_CLEAR_PROPERTY property is a DWORD value. The following option can be set:
	NcryptPinCacheClearForCallingProcessOption = 0x00000001

	NcryptKeyAccessPolicyVersion  = 1
	NcryptAllowSilentKeyAccess    = 0x00000001
	NcryptCipherKeyBlobMagic      = 0x52485043 // CPHR
	NcryptKdfKeyBlobMagic         = 0x3146444B // KDF1
	NcryptProtectedKeyBlobMagic   = 0x4B545250 // PRTK
	NcryptCipherKeyBlob           = "CipherKeyBlob"
	NcryptKdfKeyBlob              = "KDFKeyBlob"
	NcryptProtectedKeyBlob        = "ProtectedKeyBlob"
	NcryptTpmLoadableKeyBlob      = "PcpTpmProtectedKeyBlob"
	NcryptTpmLoadableKeyBlobMagic = 0x4D54504B //'MTPK'
	NcryptPkcs7EnvelopeBlob       = "PKCS7_ENVELOPE"
	NcryptPkcs8PrivateKeyBlob     = "PKCS8_PRIVATEKEY"
	NcryptOpaquetransportBlob     = "OpaqueTransport"
	NcryptIsolatedKeyEnvelopeBlob = "ISOLATED_KEY_ENVELOPE"
)

//
// NCrypt structures.
//

type NcryptCipherPaddingInfo struct {
	// size of this struct
	CbSize uint32

	// See NCRYPT_CIPHER_ flag values
	DwFlags uint32

	// [in, out, optional]
	// The address of a buffer that contains the initialization vector (IV) to use during encryption.
	// The cbIV parameter contains the size of this buffer. This function will modify the contents of this buffer.
	// If you need to reuse the IV later, make sure you make a copy of this buffer before calling this function.
	PbIV *byte // _Field_size_bytes_(cbIV)
	CbIV uint32

	// [in, out, optional]
	// The address of a buffer that contains the algorithm specific info to use during encryption.
	// The cbOtherInfo parameter contains the size of this buffer. This function will modify the contents of this buffer.
	// If you need to reuse the buffer later, make sure you make a copy of this buffer before calling this function.
	//
	// For Microsoft providers, when an authenticated encryption mode is used,
	// this parameter must point to a serialized BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure.
	//
	// NOTE: All pointers inside a structure must be to a data allocated within pbOtherInfo buffer.
	//
	PbOtherInfo *byte // _Field_size_bytes_(cbOtherInfo)
	CbOtherInfo uint32
}
type NcryptPlatformAttestPaddingInfo struct {
	Magic   uint32 // 'PAPD'
	PcrMask uint32
}
type NcryptKeyAttestPaddingInfo struct {
	Magic     uint32 // 'KAPD'
	PbKeyBlob *byte
	CbKeyBlob uint32
	PbKeyAuth *byte
	CbKeyAuth uint32
}
type NcryptIsolatedKeyAttestedAttributes struct {
	Version         uint32 // set to NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES_V0
	Flags           uint32 // NCRYPT_ISOLATED_KEY_FLAG_ flags
	CbPublicKeyBlob uint32
	// pbPublicKeyBlob[cbPublicKeyBlob] - exported public key
}
type NcryptVsmKeyAttestationStatement struct {
	Magic        uint32 // {'I', 'M', 'S', 'V'} - 'VSMI' for VSM Isolated
	Version      uint32 // Set to NCRYPT_VSM_KEY_ATTESTATION_STATEMENT_CURRENT_VERSION
	CbSignature  uint32 // Secure kernel signature over the isolation report
	CbReport     uint32 // Key isolation report from the secure kernel
	CbAttributes uint32 // Attributes of the isolated key including public key blob
	// UCHAR Signature[cbSignature]    -- Secure kernel signature of the report
	// UCHAR Report[cbReport]          -- Secure kernel report including hash of Attributes
	// UCHAR Attributes[cbAttributes]  -- Trustlet-reported attributes of the key
}
type NcryptPcpTpmWebAuthnAttestationStatement struct {
	Magic         uint32 // { 'A', 'W', 'A', 'K' } - 'KAWA'
	Version       uint32 // 1 for the statement defined in this specification
	HeaderSize    uint32 // 24
	CbCertifyInfo uint32
	CbSignature   uint32
	CbTpmPublic   uint32
	// CertifyInfo[cbCertifyInfo];
	// Signature[cbSignature];
	// TpmPublic[cbTpmPublic];
}
type NcryptTpmPlatformAttestationStatement struct {
	Magic       uint32 // {'A', 'L', 'P', 'T'} - 'TPLA' for TPM Platform
	Version     uint32 // Set to NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT_CURRENT_VERSION
	PcrAlg      uint32 // The TPM hash algorithm ID
	CbSignature uint32 // TPMT_SIGNATURE structure signature over the quote
	CbQuote     uint32 // TPMS_ATTEST structure that was generated and signed
	CbPcrs      uint32 // Raw concatenation of all 24 PCRs
	// UCHAR Signature[cbSignature]
	// UCHAR Quote[cbQuote]
	// UCHAR Pcrs[cbPcrs]
}
type NcryptAlgorithmName struct {
	PszName         *uint16
	DwClass         uint32 // the CNG interface that supports this algorithm
	DwAlgOperations uint32 // the types of operations supported by this algorithm
	DwFlags         uint32
}
type NcryptKeyName struct {
	PszName         *uint16
	PszAlgid        *uint16
	DwLegacyKeySpec uint32
	DwFlags         uint32
}
type NcryptProviderName struct {
	PszName    *uint16
	PszComment *uint16
}
type NcryptUiPolicy struct {
	DwVersion        uint32
	DwFlags          uint32
	PszCreationTitle *uint16
	PszFriendlyName  *uint16
	PszDescription   *uint16
}
type NcryptKeyAccessPolicyBlob struct {
	DwVersion        uint32
	DwPolicyFlags    uint32
	CbUserSid        uint32
	CbApplicationSid uint32
	//  User Sid
	//  Application Sid
}
type NcryptSupportedLengths struct { // NCRYPT_LENGTHS_PROPERTY property structure.
	DwMinLength     uint32
	DwMaxLength     uint32
	DwIncrement     uint32
	DwDefaultLength uint32
}
type NcryptPcpHmacAuthSignatureInfo struct { // NCRYPT_PCP_HMAC_AUTH_SIGNATURE property structure.
	DwVersion    uint32
	IExpiration  int32
	PabNonce     [32]byte
	PabPolicyRef [32]byte
	PabHMAC      [32]byte
}
type NcryptPcpTpmFwVersionInfo struct { // NCRYPT_PCP_TPM_FW_VERSION property structure.
	Major1 uint16
	Major2 uint16
	Minor1 uint16
	Minor2 uint16
}
type NcryptPcpRawPolicydigest struct { // NCRYPT_PCP_RAW_POLICYDIGEST_PROPERTY structure
	DwVersion uint32
	CbDigest  uint32
}
type NcryptKeyBlobHeader struct {
	CbSize    uint32 // size of this structure
	DwMagic   uint32
	CbAlgName uint32 // size of the algorithm, in bytes, including terminating 0
	CbKeyData uint32
}
type NcryptTpmLoadableKeyBlobHeader struct {
	Magic     uint32
	CbHeader  uint32
	CbPublic  uint32
	CbPrivate uint32
	CbName    uint32
}

//////////////////////////////////////////////////////////////////////////////////////
// DLL references.
//////////////////////////////////////////////////////////////////////////////////////

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
)

//////////////////////////////////////////////////////////////////////////////////////
// Windows error codes.
// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\shared\winerror.h.
//////////////////////////////////////////////////////////////////////////////////////

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

	// TPM Services and TPM Software Error Codes.
	tpmErrNums = map[uint32]string{
		0x80280000: "TPM_E_ERROR_MASK",
		0x80280001: "TPM_E_AUTHFAIL",
		0x80280002: "TPM_E_BADINDEX",
		0x80280003: "TPM_E_BAD_PARAMETER",
		0x80280004: "TPM_E_AUDITFAILURE",
		0x80280005: "TPM_E_CLEAR_DISABLED",
		0x80280006: "TPM_E_DEACTIVATED",
		0x80280007: "TPM_E_DISABLED",
		0x80280008: "TPM_E_DISABLED_CMD",
		0x80280009: "TPM_E_FAIL",
		0x8028000A: "TPM_E_BAD_ORDINAL",
		0x8028000B: "TPM_E_INSTALL_DISABLED",
		0x8028000C: "TPM_E_INVALID_KEYHANDLE",
		0x8028000D: "TPM_E_KEYNOTFOUND",
		0x8028000E: "TPM_E_INAPPROPRIATE_ENC",
		0x8028000F: "TPM_E_MIGRATEFAIL",
		0x80280010: "TPM_E_INVALID_PCR_INFO",
		0x80280011: "TPM_E_NOSPACE",
		0x80280012: "TPM_E_NOSRK",
		0x80280013: "TPM_E_NOTSEALED_BLOB",
		0x80280014: "TPM_E_OWNER_SET",
		0x80280015: "TPM_E_RESOURCES",
		0x80280016: "TPM_E_SHORTRANDOM",
		0x80280017: "TPM_E_SIZE",
		0x80280018: "TPM_E_WRONGPCRVAL",
		0x80280019: "TPM_E_BAD_PARAM_SIZE",
		0x8028001A: "TPM_E_SHA_THREAD",
		0x8028001B: "TPM_E_SHA_ERROR",
		0x8028001C: "TPM_E_FAILEDSELFTEST",
		0x8028001D: "TPM_E_AUTH2FAIL",
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
		0x80280030: "TPM_E_AUDITFAIL_UNSUCCESSFUL",
		0x80280031: "TPM_E_AUDITFAIL_SUCCESSFUL",
		0x80280032: "TPM_E_NOTRESETABLE",
		0x80280033: "TPM_E_NOTLOCAL",
		0x80280034: "TPM_E_BAD_TYPE",
		0x80280035: "TPM_E_INVALID_RESOURCE",
		0x80280036: "TPM_E_NOTFIPS",
		0x80280037: "TPM_E_INVALID_FAMILY",
		0x80280038: "TPM_E_NO_NV_PERMISSION",
		0x80280039: "TPM_E_REQUIRES_SIGN",
		0x8028003A: "TPM_E_KEY_NOTSUPPORTED",
		0x8028003B: "TPM_E_AUTH_CONFLICT",
		0x8028003C: "TPM_E_AREA_LOCKED",
		0x8028003D: "TPM_E_BAD_LOCALITY",
		0x8028003E: "TPM_E_READ_ONLY",
		0x8028003F: "TPM_E_PER_NOWRITE",
		0x80280040: "TPM_E_FAMILYCOUNT",
		0x80280041: "TPM_E_WRITE_LOCKED",
		0x80280042: "TPM_E_BAD_ATTRIBUTES",
		0x80280043: "TPM_E_INVALID_STRUCTURE",
		0x80280044: "TPM_E_KEY_OWNER_CONTROL",
		0x80280045: "TPM_E_BAD_COUNTER",
		0x80280046: "TPM_E_NOT_FULLWRITE",
		0x80280047: "TPM_E_CONTEXT_GAP",
		0x80280048: "TPM_E_MAXNVWRITES",
		0x80280049: "TPM_E_NOOPERATOR",
		0x8028004A: "TPM_E_RESOURCEMISSING",
		0x8028004B: "TPM_E_DELEGATE_LOCK",
		0x8028004C: "TPM_E_DELEGATE_FAMILY",
		0x8028004D: "TPM_E_DELEGATE_ADMIN",
		0x8028004E: "TPM_E_TRANSPORT_NOTEXCLUSIVE",
		0x8028004F: "TPM_E_OWNER_CONTROL",
		0x80280050: "TPM_E_DAA_RESOURCES",
		0x80280051: "TPM_E_DAA_INPUT_DATA0",
		0x80280052: "TPM_E_DAA_INPUT_DATA1",
		0x80280053: "TPM_E_DAA_ISSUER_SETTINGS",
		0x80280054: "TPM_E_DAA_TPM_SETTINGS",
		0x80280055: "TPM_E_DAA_STAGE",
		0x80280056: "TPM_E_DAA_ISSUER_VALIDITY",
		0x80280057: "TPM_E_DAA_WRONG_W",
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
		0x80280081: "TPM_20_E_ASYMMETRIC",
		0x80280082: "TPM_20_E_ATTRIBUTES",
		0x80280083: "TPM_20_E_HASH",
		0x80280084: "TPM_20_E_VALUE",
		0x80280085: "TPM_20_E_HIERARCHY",
		0x80280087: "TPM_20_E_KEY_SIZE",
		0x80280088: "TPM_20_E_MGF",
		0x80280089: "TPM_20_E_MODE",
		0x8028008A: "TPM_20_E_TYPE",
		0x8028008B: "TPM_20_E_HANDLE",
		0x8028008C: "TPM_20_E_KDF",
		0x8028008D: "TPM_20_E_RANGE",
		0x8028008E: "TPM_20_E_AUTH_FAIL",
		0x8028008F: "TPM_20_E_NONCE",
		0x80280090: "TPM_20_E_PP",
		0x80280092: "TPM_20_E_SCHEME",
		0x80280095: "TPM_20_E_SIZE",
		0x80280096: "TPM_20_E_SYMMETRIC",
		0x80280097: "TPM_20_E_TAG",
		0x80280098: "TPM_20_E_SELECTOR",
		0x8028009A: "TPM_20_E_INSUFFICIENT",
		0x8028009B: "TPM_20_E_SIGNATURE",
		0x8028009C: "TPM_20_E_KEY",
		0x8028009D: "TPM_20_E_POLICY_FAIL",
		0x8028009F: "TPM_20_E_INTEGRITY",
		0x802800A0: "TPM_20_E_TICKET",
		0x802800A1: "TPM_20_E_RESERVED_BITS",
		0x802800A2: "TPM_20_E_BAD_AUTH",
		0x802800A3: "TPM_20_E_EXPIRED",
		0x802800A4: "TPM_20_E_POLICY_CC",
		0x802800A5: "TPM_20_E_BINDING",
		0x802800A6: "TPM_20_E_CURVE",
		0x802800A7: "TPM_20_E_ECC_POINT",
		0x80280100: "TPM_20_E_INITIALIZE",
		0x80280101: "TPM_20_E_FAILURE",
		0x80280103: "TPM_20_E_SEQUENCE",
		0x8028010B: "TPM_20_E_PRIVATE",
		0x80280119: "TPM_20_E_HMAC",
		0x80280120: "TPM_20_E_DISABLED",
		0x80280121: "TPM_20_E_EXCLUSIVE",
		0x80280123: "TPM_20_E_ECC_CURVE",
		0x80280124: "TPM_20_E_AUTH_TYPE",
		0x80280125: "TPM_20_E_AUTH_MISSING",
		0x80280126: "TPM_20_E_POLICY",
		0x80280127: "TPM_20_E_PCR",
		0x80280128: "TPM_20_E_PCR_CHANGED",
		0x8028012D: "TPM_20_E_UPGRADE",
		0x8028012E: "TPM_20_E_TOO_MANY_CONTEXTS",
		0x8028012F: "TPM_20_E_AUTH_UNAVAILABLE",
		0x80280130: "TPM_20_E_REBOOT",
		0x80280131: "TPM_20_E_UNBALANCED",
		0x80280142: "TPM_20_E_COMMAND_SIZE",
		0x80280143: "TPM_20_E_COMMAND_CODE",
		0x80280144: "TPM_20_E_AUTHSIZE",
		0x80280145: "TPM_20_E_AUTH_CONTEXT",
		0x80280146: "TPM_20_E_NV_RANGE",
		0x80280147: "TPM_20_E_NV_SIZE",
		0x80280148: "TPM_20_E_NV_LOCKED",
		0x80280149: "TPM_20_E_NV_AUTHORIZATION",
		0x8028014A: "TPM_20_E_NV_UNINITIALIZED",
		0x8028014B: "TPM_20_E_NV_SPACE",
		0x8028014C: "TPM_20_E_NV_DEFINED",
		0x80280150: "TPM_20_E_BAD_CONTEXT",
		0x80280151: "TPM_20_E_CPHASH",
		0x80280152: "TPM_20_E_PARENT",
		0x80280153: "TPM_20_E_NEEDS_TEST",
		0x80280154: "TPM_20_E_NO_RESULT",
		0x80280155: "TPM_20_E_SENSITIVE",
		0x80280400: "TPM_E_COMMAND_BLOCKED",
		0x80280401: "TPM_E_INVALID_HANDLE",
		0x80280402: "TPM_E_DUPLICATE_VHANDLE",
		0x80280403: "TPM_E_EMBEDDED_COMMAND_BLOCKED",
		0x80280404: "TPM_E_EMBEDDED_COMMAND_UNSUPPORTED",
		0x80280800: "TPM_E_RETRY",
		0x80280801: "TPM_E_NEEDS_SELFTEST",
		0x80280802: "TPM_E_DOING_SELFTEST",
		0x80280803: "TPM_E_DEFEND_LOCK_RUNNING",
		0x80280901: "TPM_20_E_CONTEXT_GAP",
		0x80280902: "TPM_20_E_OBJECT_MEMORY",
		0x80280903: "TPM_20_E_SESSION_MEMORY",
		0x80280904: "TPM_20_E_MEMORY",
		0x80280905: "TPM_20_E_SESSION_HANDLES",
		0x80280906: "TPM_20_E_OBJECT_HANDLES",
		0x80280907: "TPM_20_E_LOCALITY",
		0x80280908: "TPM_20_E_YIELDED",
		0x80280909: "TPM_20_E_CANCELED",
		0x8028090A: "TPM_20_E_TESTING",
		0x80280920: "TPM_20_E_NV_RATE",
		0x80280921: "TPM_20_E_LOCKOUT",
		0x80280922: "TPM_20_E_RETRY",
		0x80280923: "TPM_20_E_NV_UNAVAILABLE",
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
		0x80290100: "TPMAPI_E_INVALID_STATE",
		0x80290101: "TPMAPI_E_NOT_ENOUGH_DATA",
		0x80290102: "TPMAPI_E_TOO_MUCH_DATA",
		0x80290103: "TPMAPI_E_INVALID_OUTPUT_POINTER",
		0x80290104: "TPMAPI_E_INVALID_PARAMETER",
		0x80290105: "TPMAPI_E_OUT_OF_MEMORY",
		0x80290106: "TPMAPI_E_BUFFER_TOO_SMALL",
		0x80290107: "TPMAPI_E_INTERNAL_ERROR",
		0x80290108: "TPMAPI_E_ACCESS_DENIED",
		0x80290109: "TPMAPI_E_AUTHORIZATION_FAILED",
		0x8029010A: "TPMAPI_E_INVALID_CONTEXT_HANDLE",
		0x8029010B: "TPMAPI_E_TBS_COMMUNICATION_ERROR",
		0x8029010C: "TPMAPI_E_TPM_COMMAND_ERROR",
		0x8029010D: "TPMAPI_E_MESSAGE_TOO_LARGE",
		0x8029010E: "TPMAPI_E_INVALID_ENCODING",
		0x8029010F: "TPMAPI_E_INVALID_KEY_SIZE",
		0x80290110: "TPMAPI_E_ENCRYPTION_FAILED",
		0x80290111: "TPMAPI_E_INVALID_KEY_PARAMS",
		0x80290112: "TPMAPI_E_INVALID_MIGRATION_AUTHORIZATION_BLOB",
		0x80290113: "TPMAPI_E_INVALID_PCR_INDEX",
		0x80290114: "TPMAPI_E_INVALID_DELEGATE_BLOB",
		0x80290115: "TPMAPI_E_INVALID_CONTEXT_PARAMS",
		0x80290116: "TPMAPI_E_INVALID_KEY_BLOB",
		0x80290117: "TPMAPI_E_INVALID_PCR_DATA",
		0x80290118: "TPMAPI_E_INVALID_OWNER_AUTH",
		0x80290119: "TPMAPI_E_FIPS_RNG_CHECK_FAILED",
		0x8029011A: "TPMAPI_E_EMPTY_TCG_LOG",
		0x8029011B: "TPMAPI_E_INVALID_TCG_LOG_ENTRY",
		0x8029011C: "TPMAPI_E_TCG_SEPARATOR_ABSENT",
		0x8029011D: "TPMAPI_E_TCG_INVALID_DIGEST_ENTRY",
		0x8029011E: "TPMAPI_E_POLICY_DENIES_OPERATION",
		0x8029011F: "TPMAPI_E_NV_BITS_NOT_DEFINED",
		0x80290120: "TPMAPI_E_NV_BITS_NOT_READY",
		0x80290121: "TPMAPI_E_SEALING_KEY_NOT_AVAILABLE",
		0x80290122: "TPMAPI_E_NO_AUTHORIZATION_CHAIN_FOUND",
		0x80290123: "TPMAPI_E_SVN_COUNTER_NOT_AVAILABLE",
		0x80290124: "TPMAPI_E_OWNER_AUTH_NOT_NULL",
		0x80290125: "TPMAPI_E_ENDORSEMENT_AUTH_NOT_NULL",
		0x80290126: "TPMAPI_E_AUTHORIZATION_REVOKED",
		0x80290127: "TPMAPI_E_MALFORMED_AUTHORIZATION_KEY",
		0x80290128: "TPMAPI_E_AUTHORIZING_KEY_NOT_SUPPORTED",
		0x80290129: "TPMAPI_E_INVALID_AUTHORIZATION_SIGNATURE",
		0x8029012A: "TPMAPI_E_MALFORMED_AUTHORIZATION_POLICY",
		0x8029012B: "TPMAPI_E_MALFORMED_AUTHORIZATION_OTHER",
		0x8029012C: "TPMAPI_E_SEALING_KEY_CHANGED",
		0x8029012D: "TPMAPI_E_INVALID_TPM_VERSION",
		0x8029012E: "TPMAPI_E_INVALID_POLICYAUTH_BLOB_TYPE",
		0x80290200: "TBSIMP_E_BUFFER_TOO_SMALL",
		0x80290201: "TBSIMP_E_CLEANUP_FAILED",
		0x80290202: "TBSIMP_E_INVALID_CONTEXT_HANDLE",
		0x80290203: "TBSIMP_E_INVALID_CONTEXT_PARAM",
		0x80290204: "TBSIMP_E_TPM_ERROR",
		0x80290205: "TBSIMP_E_HASH_BAD_KEY",
		0x80290206: "TBSIMP_E_DUPLICATE_VHANDLE",
		0x80290207: "TBSIMP_E_INVALID_OUTPUT_POINTER",
		0x80290208: "TBSIMP_E_INVALID_PARAMETER",
		0x80290209: "TBSIMP_E_RPC_INIT_FAILED",
		0x8029020A: "TBSIMP_E_SCHEDULER_NOT_RUNNING",
		0x8029020B: "TBSIMP_E_COMMAND_CANCELED",
		0x8029020C: "TBSIMP_E_OUT_OF_MEMORY",
		0x8029020D: "TBSIMP_E_LIST_NO_MORE_ITEMS",
		0x8029020E: "TBSIMP_E_LIST_NOT_FOUND",
		0x8029020F: "TBSIMP_E_NOT_ENOUGH_SPACE",
		0x80290210: "TBSIMP_E_NOT_ENOUGH_TPM_CONTEXTS",
		0x80290211: "TBSIMP_E_COMMAND_FAILED",
		0x80290212: "TBSIMP_E_UNKNOWN_ORDINAL",
		0x80290213: "TBSIMP_E_RESOURCE_EXPIRED",
		0x80290214: "TBSIMP_E_INVALID_RESOURCE",
		0x80290215: "TBSIMP_E_NOTHING_TO_UNLOAD",
		0x80290216: "TBSIMP_E_HASH_TABLE_FULL",
		0x80290217: "TBSIMP_E_TOO_MANY_TBS_CONTEXTS",
		0x80290218: "TBSIMP_E_TOO_MANY_RESOURCES",
		0x80290219: "TBSIMP_E_PPI_NOT_SUPPORTED",
		0x8029021A: "TBSIMP_E_TPM_INCOMPATIBLE",
		0x8029021B: "TBSIMP_E_NO_EVENT_LOG",
		0x80290300: "TPM_E_PPI_ACPI_FAILURE",
		0x80290301: "TPM_E_PPI_USER_ABORT",
		0x80290302: "TPM_E_PPI_BIOS_FAILURE",
		0x80290303: "TPM_E_PPI_NOT_SUPPORTED",
		0x80290304: "TPM_E_PPI_BLOCKED_IN_BIOS",
		0x80290400: "TPM_E_PCP_ERROR_MASK",
		0x80290401: "TPM_E_PCP_DEVICE_NOT_READY",
		0x80290402: "TPM_E_PCP_INVALID_HANDLE",
		0x80290403: "TPM_E_PCP_INVALID_PARAMETER",
		0x80290404: "TPM_E_PCP_FLAG_NOT_SUPPORTED",
		0x80290405: "TPM_E_PCP_NOT_SUPPORTED",
		0x80290406: "TPM_E_PCP_BUFFER_TOO_SMALL",
		0x80290407: "TPM_E_PCP_INTERNAL_ERROR",
		0x80290408: "TPM_E_PCP_AUTHENTICATION_FAILED",
		0x80290409: "TPM_E_PCP_AUTHENTICATION_IGNORED",
		0x8029040A: "TPM_E_PCP_POLICY_NOT_FOUND",
		0x8029040B: "TPM_E_PCP_PROFILE_NOT_FOUND",
		0x8029040C: "TPM_E_PCP_VALIDATION_FAILED",
		0x8029040E: "TPM_E_PCP_WRONG_PARENT",
		0x8029040F: "TPM_E_KEY_NOT_LOADED",
		0x80290410: "TPM_E_NO_KEY_CERTIFICATION",
		0x80290411: "TPM_E_KEY_NOT_FINALIZED",
		0x80290412: "TPM_E_ATTESTATION_CHALLENGE_NOT_SET",
		0x80290413: "TPM_E_NOT_PCR_BOUND",
		0x80290414: "TPM_E_KEY_ALREADY_FINALIZED",
		0x80290415: "TPM_E_KEY_USAGE_POLICY_NOT_SUPPORTED",
		0x80290416: "TPM_E_KEY_USAGE_POLICY_INVALID",
		0x80290417: "TPM_E_SOFT_KEY_ERROR",
		0x80290418: "TPM_E_KEY_NOT_AUTHENTICATED",
		0x80290419: "TPM_E_PCP_KEY_NOT_AIK",
		0x8029041A: "TPM_E_KEY_NOT_SIGNING_KEY",
		0x8029041B: "TPM_E_LOCKED_OUT",
		0x8029041C: "TPM_E_CLAIM_TYPE_NOT_SUPPORTED",
		0x8029041D: "TPM_E_VERSION_NOT_SUPPORTED",
		0x8029041E: "TPM_E_BUFFER_LENGTH_MISMATCH",
		0x8029041F: "TPM_E_PCP_IFX_RSA_KEY_CREATION_BLOCKED",
		0x80290420: "TPM_E_PCP_TICKET_MISSING",
		0x80290421: "TPM_E_PCP_RAW_POLICY_NOT_SUPPORTED",
		0x80290422: "TPM_E_PCP_KEY_HANDLE_INVALIDATED",
		0x40290423: "TPM_E_PCP_UNSUPPORTED_PSS_SALT",
		0x40290424: "TPM_E_PCP_PLATFORM_CLAIM_MAY_BE_OUTDATED",
		0x40290425: "TPM_E_PCP_PLATFORM_CLAIM_OUTDATED",
		0x40290426: "TPM_E_PCP_PLATFORM_CLAIM_REBOOT",
		0x80290500: "TPM_E_ZERO_EXHAUST_ENABLED",
		0x80290600: "TPM_E_PROVISIONING_INCOMPLETE",
		0x80290601: "TPM_E_INVALID_OWNER_AUTH",
		0x80290602: "TPM_E_TOO_MUCH_DATA",
	}

	// Other Error Codes.
	otherWinErrNums = map[uint32]string{
		0x80090001: "NTE_BAD_UID",
		0x80090002: "NTE_BAD_HASH",
		0x80090003: "NTE_BAD_KEY",
		0x80090004: "NTE_BAD_LEN",
		0x80090005: "NTE_BAD_DATA",
		0x80090006: "NTE_BAD_SIGNATURE",
		0x80090007: "NTE_BAD_VER",
		0x80090008: "NTE_BAD_ALGID",
		0x80090009: "NTE_BAD_FLAGS",
		0x8009000A: "NTE_BAD_TYPE",
		0x8009000B: "NTE_BAD_KEY_STATE",
		0x8009000C: "NTE_BAD_HASH_STATE",
		0x8009000D: "NTE_NO_KEY",
		0x8009000E: "NTE_NO_MEMORY",
		0x8009000F: "NTE_EXISTS",
		0x80090010: "NTE_PERM",
		0x80090011: "NTE_NOT_FOUND",
		0x80090012: "NTE_DOUBLE_ENCRYPT",
		0x80090013: "NTE_BAD_PROVIDER",
		0x80090014: "NTE_BAD_PROV_TYPE",
		0x80090015: "NTE_BAD_PUBLIC_KEY",
		0x80090016: "NTE_BAD_KEYSET",
		0x80090017: "NTE_PROV_TYPE_NOT_DEF",
		0x80090018: "NTE_PROV_TYPE_ENTRY_BAD",
		0x80090019: "NTE_KEYSET_NOT_DEF",
		0x8009001A: "NTE_KEYSET_ENTRY_BAD",
		0x8009001B: "NTE_PROV_TYPE_NO_MATCH",
		0x8009001C: "NTE_SIGNATURE_FILE_BAD",
		0x8009001D: "NTE_PROVIDER_DLL_FAIL",
		0x8009001E: "NTE_PROV_DLL_NOT_FOUND",
		0x8009001F: "NTE_BAD_KEYSET_PARAM",
		0x80090020: "NTE_FAIL",
		0x80090021: "NTE_SYS_ERR",
		0x80090022: "NTE_SILENT_CONTEXT",
		0x80090023: "NTE_TOKEN_KEYSET_STORAGE_FULL",
		0x80090024: "NTE_TEMPORARY_PROFILE",
		0x80090025: "NTE_FIXEDPARAMETER",
		0x80090026: "NTE_INVALID_HANDLE",
		0x80090027: "NTE_INVALID_PARAMETER",
		0x80090028: "NTE_BUFFER_TOO_SMALL",
		0x80090029: "NTE_NOT_SUPPORTED",
		0x8009002A: "NTE_NO_MORE_ITEMS",
		0x8009002B: "NTE_BUFFERS_OVERLAP",
		0x8009002C: "NTE_DECRYPTION_FAILURE",
		0x8009002D: "NTE_INTERNAL_ERROR",
		0x8009002E: "NTE_UI_REQUIRED",
		0x8009002F: "NTE_HMAC_NOT_SUPPORTED",
		0x80090030: "NTE_DEVICE_NOT_READY",
		0x80090031: "NTE_AUTHENTICATION_IGNORED",
		0x80090032: "NTE_VALIDATION_FAILED",
		0x80090033: "NTE_INCORRECT_PASSWORD",
		0x80090034: "NTE_ENCRYPTION_FAILURE",
		0x80090035: "NTE_DEVICE_NOT_FOUND",
		0x80090036: "NTE_USER_CANCELLED",
		0x80090037: "NTE_PASSWORD_CHANGE_REQUIRED",
		0x80090038: "NTE_NOT_ACTIVE_CONSOLE",
	}
)

func maybeWinErr(errNo uintptr) error {
	if code, known := tpmErrNums[uint32(errNo)]; known {
		return fmt.Errorf("tpm or subsystem failure: (%X) %s", errNo, code)
	} else if code, known := otherWinErrNums[uint32(errNo)]; known {
		return fmt.Errorf("failure code: (%X) %s", errNo, code)
	} else {
		return fmt.Errorf("errno code: (%X) %s", errNo, syscall.Errno(errNo))
	}
}

// Utf16BytesToString transforms a []byte which contains a wide char string in LE
// into its []uint16 corresponding representation,
// then returns the UTF-8 encoding of the UTF-16 sequence,
// with a terminating NUL removed. If after converting the []byte into
// a []uint16, there is a NUL uint16, the conversion to string stops
// at that NUL uint16.
func Utf16BytesToString(buf []byte) (string, error) {

	if len(buf)%2 != 0 {
		return "", fmt.Errorf("input is not a valid byte representation of a wide char string in LE")
	}
	b := make([]uint16, len(buf)/2)

	// LPCSTR (Windows' representation of utf16) is always little endian.
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, b); err != nil {
		return "", err
	}
	return windows.UTF16ToString(b), nil
}

// Utf16ToString transforms a []utf16 which contains a wide char string in LE
// into its UTF-8 encoding representation, with a terminating NUL removed.
// The conversion stops at the first encountered NUL uint16.
func Utf16ToString(buf []uint16) (string, error) {
	return windows.UTF16ToString(buf), nil
}

// Utf16PtrToString transforms a *utf16 which contains a wide char string in LE
// into its UTF-8 encoding representation, with a terminating NUL removed.
// The conversion stops at the first encountered NUL uint16.
func Utf16PtrToString(buf *uint16) string {
	return windows.UTF16PtrToString(buf)
}

// StringToUtf16Ptr returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func StringToUtf16(str string) ([]uint16, error) {
	if str == "" {
		return nil, nil
	}
	return windows.UTF16FromString(str)
}

// StringToUtf16Ptr returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func StringToUtf16Ptr(str string) (*uint16, error) {
	if str == "" {
		return nil, nil
	}
	return windows.UTF16PtrFromString(str)
}

// BytesToUtf16Ptr returns the UTF-16 encoding of the UTF-8 string
// contained in buf as a byte array, with a terminating NUL added.
// If str contains a NUL byte at any location, it returns (nil, EINVAL).
func BytesToUtf16Ptr(buf []byte) (*uint16, error) {
	str := string(buf)
	return StringToUtf16Ptr(str)
}

// BytesToUtf16 returns the UTF-16 encoding of the UTF-8 string
// contained in buf as a byte array, with a terminating NUL added.
// If str contains a NUL byte at any location, it returns (nil, EINVAL).
func BytesToUtf16(buf []byte) ([]uint16, error) {
	str := string(buf)
	return StringToUtf16(str)
}

// StringToUtf16Bytes returns the UTF-16 encoding of the UTF-8 string
// str, as a byte array with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func StringToUtf16Bytes(str string) ([]byte, error) {
	if str == "" {
		return nil, nil
	}
	utf16Str, err := windows.UTF16FromString(str)
	if err != nil {
		return nil, err
	}
	bytesStr := make([]byte, len(utf16Str)*2)
	j := 0
	for _, utf16 := range utf16Str {
		b := make([]byte, 2)
		// LPCSTR (Windows' representation of utf16) is always little endian.
		binary.LittleEndian.PutUint16(b, utf16)
		bytesStr[j] = b[0]
		bytesStr[j+1] = b[1]
		j += 2
	}
	return bytesStr, nil
}

// StringToUtf16String returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func StringToUtf16String(str string) ([]uint16, error) {
	if str == "" {
		return nil, nil
	}
	utf16Str, err := windows.UTF16FromString(str)
	if err != nil {
		return nil, err
	}
	return utf16Str, nil
}

//////////////////////////////////////////////////////////////////////////////////////

func NCryptCreateClaim(
	hSubjectKey uintptr, /* NCRYPT_KEY_HANDLE */
	hAuthorityKey uintptr, /* NCRYPT_KEY_HANDLE */
	dwClaimType uint32, /* DWORD */
	pParameterList *BcryptBufferDesc, /* NCryptBufferDesc* */
	dwFlags uint32, /* DWORD */
) ([]byte, uint32, error) {

	var size uint32
	r, _, msg := nCryptCreateClaimProc.Call(
		uintptr(hSubjectKey),
		uintptr(hAuthorityKey),
		uintptr(dwClaimType),
		uintptr(unsafe.Pointer(pParameterList)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptCreateClaim() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptCreateClaim() returned an empty output")
	}

	pbClaimData := make([]byte, size)
	r, _, msg = nCryptCreateClaimProc.Call(
		uintptr(hSubjectKey),
		uintptr(hAuthorityKey),
		uintptr(dwClaimType),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(&pbClaimData[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptCreateClaim() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptCreateClaim() returned an empty output")
	}

	return pbClaimData, 0, nil
}

func NCryptCreatePersistedKey(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	hKey *uintptr, /* NCRYPT_KEY_HANDLE* */
	pszAlgID string, /* LPCWSTR : Common algorithm identifier */
	pszKeyName string, /* LPCWSTR */
	dwLegacyKeySpec uint32, /* DWORD */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	utf16AlgID, err := StringToUtf16Ptr(pszAlgID)
	if err != nil {
		return 0, err
	}

	utf16KeyName, err := StringToUtf16Ptr(pszKeyName)
	if err != nil {
		return 0, err
	}

	r, _, msg := nCryptCreatePersistedKeyProc.Call(
		uintptr(hProvider),
		uintptr(unsafe.Pointer(hKey)),
		uintptr(unsafe.Pointer(utf16AlgID)),
		uintptr(unsafe.Pointer(utf16KeyName)),
		uintptr(dwLegacyKeySpec),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptCreatePersistedKey() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptDecrypt(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	pbInput []byte, /* PBYTE */
	pPaddingInfo unsafe.Pointer, /* VOID* */
	dwFlags uint32, /* DWORD */
) ([]byte, uint32, error) {

	var size uint32
	r, _, msg := nCryptDecryptProc.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(&pbInput[0])),
		uintptr(len(pbInput)),
		uintptr(pPaddingInfo),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptDecrypt() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptDecrypt() returned an empty output")
	}

	decryptedData := make([]byte, size)
	r, _, msg = nCryptDecryptProc.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(&pbInput[0])),
		uintptr(len(pbInput)),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&decryptedData[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptDecrypt() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptDecrypt() returned an empty output")
	}

	return decryptedData, 0, nil
}

func NCryptDeleteKey(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	r, _, msg := nCryptDeleteKeyProc.Call(
		uintptr(hKey),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptDeleteKey() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptDeriveKey(
	hSharedSecret uintptr, /* NCRYPT_SECRET_HANDLE */
	pwszKDF string, /* LPCWSTR */
	pParameterList *BcryptBufferDesc, /* NCryptBufferDesc* */
	dwFlags uint32, /* DWORD */
) ([]byte, uint32, error) {

	utf16KDF, err := windows.UTF16FromString(pwszKDF)
	if err != nil {
		return nil, 0, err
	}

	var size uint32
	r, _, msg := nCryptDeriveKeyProc.Call(
		uintptr(hSharedSecret),
		uintptr(unsafe.Pointer(&utf16KDF[0])),
		uintptr(unsafe.Pointer(pParameterList)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptDeriveKey() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptDeriveKey() returned an empty output")
	}

	derivedData := make([]byte, size)
	r, _, msg = nCryptDeriveKeyProc.Call(
		uintptr(hSharedSecret),
		uintptr(unsafe.Pointer(&utf16KDF[0])),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(&derivedData[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptDeriveKey() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptDeriveKey() returned an empty output")
	}

	return derivedData, 0, nil
}

func NCryptEncrypt(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	pbInput []byte, /* PBYTE */
	pPaddingInfo unsafe.Pointer, /* VOID* */
	dwFlags uint32, /* DWORD */
) ([]byte, uint32, error) {

	var size uint32
	r, _, msg := nCryptEncryptProc.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(&pbInput[0])),
		uintptr(len(pbInput)),
		uintptr(pPaddingInfo),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptEncrypt() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptEncrypt() returned an empty output")
	}

	encryptedData := make([]byte, size)
	r, _, msg = nCryptEncryptProc.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(&pbInput[0])),
		uintptr(len(pbInput)),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&encryptedData[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptEncrypt() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptEncrypt() returned an empty output")
	}

	return encryptedData, 0, nil
}

func NCryptEnumAlgorithms(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	dwAlgOperations uint32, /* DWORD */
	pdwAlgCount *uint32, /* DWORD* */
	ppAlgList *unsafe.Pointer, /* NCryptAlgorithmName** */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	r, _, msg := nCryptEnumAlgorithmsProc.Call(
		uintptr(hProvider),
		uintptr(dwAlgOperations),
		uintptr(unsafe.Pointer(pdwAlgCount)),
		uintptr(unsafe.Pointer(ppAlgList)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptEnumAlgorithms() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptEnumKeys(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	pszScope string, /* LPCWSTR */
	ppKeyName *unsafe.Pointer, /* NCryptKeyName** */
	ppEnumState *unsafe.Pointer, /* PVOID* */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	utf16Property, err := StringToUtf16Ptr(pszScope)
	if err != nil {
		return 0, err
	}

	r, _, msg := nCryptEnumKeysProc.Call(
		uintptr(hProvider),
		uintptr(unsafe.Pointer(utf16Property)),
		uintptr(unsafe.Pointer(ppKeyName)),
		uintptr(unsafe.Pointer(ppEnumState)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptEnumKeys() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptEnumStorageProviders(
	pdwProviderCount *uint32, /* DWORD* */
	ppProviderList *unsafe.Pointer, /* NCryptProviderName** */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	r, _, msg := nCryptEnumStorageProvidersProc.Call(
		uintptr(unsafe.Pointer(pdwProviderCount)),
		uintptr(unsafe.Pointer(ppProviderList)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptEnumStorageProvidersProc() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptExportKey(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	hExportKey uintptr, /* NCRYPT_KEY_HANDLE */
	pszBlobType string, /* LPCWSTR */
	pParameterList *BcryptBufferDesc, /* NCryptBufferDesc* */
	dwFlags uint32, /* DWORD */
) ([]byte, uint32, error) {

	var size uint32

	utf16BlobType, err := StringToUtf16Ptr(pszBlobType)
	if err != nil {
		return nil, 0, err
	}

	r, _, msg := nCryptExportKeyProc.Call(
		uintptr(hKey),
		uintptr(hExportKey),
		uintptr(unsafe.Pointer(utf16BlobType)),
		uintptr(unsafe.Pointer(pParameterList)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptExportKey() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptExportKey() returned an empty output")
	}

	exportedKey := make([]byte, size)
	r, _, msg = nCryptExportKeyProc.Call(
		uintptr(hKey),
		uintptr(hExportKey),
		uintptr(unsafe.Pointer(utf16BlobType)),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(&exportedKey[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptExportKey() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptExportKey() returned an empty output")
	}

	return exportedKey, 0, nil
}

func NCryptFinalizeKey(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	r, _, msg := nCryptFinalizeKeyProc.Call(
		uintptr(hKey),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptFinalizeKey() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptFreeBuffer(
	pvInput unsafe.Pointer, /* PVOID */
) (uint32, error) {

	r, _, msg := nCryptFreeBufferProc.Call(
		uintptr(pvInput),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptFreeBuffer() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptFreeObject(
	hObject uintptr, /* NCRYPT_HANDLE */
) (uint32, error) {

	r, _, msg := nCryptFreeObjectProc.Call(
		uintptr(hObject),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptFreeObject() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptGetProperty(
	hObject uintptr, /* NCRYPT_HANDLE */
	pszProperty string, /* LPCWSTR */
	dwFlags uint32, /* DWORD */
) ([]byte, uint32, error) {

	var size uint32

	utf16Property, err := StringToUtf16Ptr(pszProperty)
	if err != nil {
		return nil, 0, err
	}

	r, _, msg := nCryptGetPropertyProc.Call(
		uintptr(hObject),
		uintptr(unsafe.Pointer(utf16Property)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptGetProperty() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptGetProperty() returned an empty output")
	}

	propertyData := make([]byte, size)
	r, _, msg = nCryptGetPropertyProc.Call(
		uintptr(hObject),
		uintptr(unsafe.Pointer(utf16Property)),
		uintptr(unsafe.Pointer(&propertyData[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptGetProperty() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptGetProperty() returned an empty output")
	}

	return propertyData, 0, nil
}

func NCryptImportKey(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	hImportKey uintptr, /* NCRYPT_KEY_HANDLE */
	pszBlobType string, /* LPCWSTR */
	pParameterList *BcryptBufferDesc, /* NCryptBufferDesc* */
	phKey *uintptr, /* NCRYPT_KEY_HANDLE* */
	pbData []byte, /* PBYTE */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	utf16BlobType, err := StringToUtf16Ptr(pszBlobType)
	if err != nil {
		return 0, err
	}

	r, _, msg := nCryptImportKeyProc.Call(
		uintptr(hProvider),
		uintptr(hImportKey),
		uintptr(unsafe.Pointer(utf16BlobType)),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(phKey)),
		uintptr(unsafe.Pointer(&pbData[0])),
		uintptr(len(pbData)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptImportKey() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptIsAlgSupported(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	pszAlgID string, /* LPCWSTR */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	utf16AlgID, err := StringToUtf16Ptr(pszAlgID)
	if err != nil {
		return 0, err
	}

	r, _, msg := nCryptIsAlgSupportedProc.Call(
		uintptr(hProvider),
		uintptr(unsafe.Pointer(utf16AlgID)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return 0, fmt.Errorf("nCryptIsAlgSupported() returned %X (%v)", r, msg)
	}

	return uint32(r), nil
}

func NCryptIsKeyHandle(
	hKey uintptr, /* NCRYPT_PROV_HANDLE */
) bool {

	r, _, _ := nCryptIsKeyHandleProc.Call(
		uintptr(hKey),
	)
	return r != 0
}

func NCryptKeyDerivation(
	hKey uintptr, /* NCRYPT_PROV_HANDLE */
	pParameterList *BcryptBufferDesc, /* NCryptBufferDesc* */
	pbDerivedKey *byte, /* PUCHAR */
	cbDerivedKey uint32, /* DWORD */
	pcbResult *uint32, /* DWORD* */
	dwFlags uint32, /* ULONG */
) (uint32, error) {

	r, _, msg := nCryptKeyDerivationProc.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(pbDerivedKey)),
		uintptr(cbDerivedKey),
		uintptr(unsafe.Pointer(pcbResult)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptKeyDerivation() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptOpenKey(
	hProvider uintptr, /* NCRYPT_PROV_HANDLE */
	phKey *uintptr, /* NCRYPT_KEY_HANDLE* */
	pszKeyName string, /* LPCWSTR */
	dwLegacyKeySpec uint32, /* DWORD */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	utf16KeyName, err := StringToUtf16Ptr(pszKeyName)
	if err != nil {
		return 0, err
	}

	r, _, msg := nCryptOpenKeyProc.Call(
		uintptr(hProvider),
		uintptr(unsafe.Pointer(phKey)),
		uintptr(unsafe.Pointer(utf16KeyName)),
		uintptr(dwLegacyKeySpec),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptOpenKey() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptOpenStorageProvider(
	phProvider *uintptr, /* NCRYPT_PROV_HANDLE* */
	pszProviderName string, /* LPCWSTR */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	utf16ProviderName, err := StringToUtf16Ptr(pszProviderName)
	if err != nil {
		return 0, err
	}

	r, _, msg := nCryptOpenStorageProviderProc.Call(
		uintptr(unsafe.Pointer(phProvider)),
		uintptr(unsafe.Pointer(utf16ProviderName)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptOpenStorageProvider() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptSecretAgreement(
	hPrivKey uintptr, /* NCRYPT_KEY_HANDLE */
	hPubKey uintptr, /* NCRYPT_KEY_HANDLE */
	phAgreedSecret *uintptr, /* NCRYPT_SECRET_HANDLE* */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	r, _, msg := nCryptSecretAgreementProc.Call(
		uintptr(hPrivKey),
		uintptr(hPubKey),
		uintptr(unsafe.Pointer(phAgreedSecret)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptSecretAgreement() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptSetProperty(
	hObject uintptr, /* NCRYPT_HANDLE */
	pszProperty string, /* LPCWSTR */
	pbInput []byte, /* PBYTE */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	utf16Property, err := StringToUtf16Ptr(pszProperty)
	if err != nil {
		return 0, err
	}

	r, _, msg := nCryptSetPropertyProc.Call(
		uintptr(hObject),
		uintptr(unsafe.Pointer(utf16Property)),
		uintptr(unsafe.Pointer(&pbInput[0])),
		uintptr(len(pbInput)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptSetProperty() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptSignHash(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	pPaddingInfo unsafe.Pointer, /* VOID* */
	pbHashValue []byte, /* PBYTE */
	dwFlags uint32, /* DWORD */
) ([]byte, uint32, error) {

	var size uint32
	r, _, msg := nCryptSignHashProc.Call(
		uintptr(hKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&pbHashValue[0])),
		uintptr(len(pbHashValue)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptSignHash() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptSignHash() returned an empty output")
	}

	signedData := make([]byte, size)
	r, _, msg = nCryptSignHashProc.Call(
		uintptr(hKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&pbHashValue[0])),
		uintptr(len(pbHashValue)),
		uintptr(unsafe.Pointer(&signedData[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return nil, uint32(r), fmt.Errorf("nCryptSignHash() returned %X (%v)", r, msg)
	}
	if size == 0 {
		return nil, 0, fmt.Errorf("nCryptSignHash() returned an empty output")
	}

	return signedData, 0, nil
}

func NCryptTranslateHandle(
	phProvider *uintptr, /* NCRYPT_PROV_HANDLE* */
	phKey *uintptr, /* NCRYPT_KEY_HANDLE* */
	hLegacyProv uintptr, /* HCRYPTPROV */
	hLegacyKey uintptr, /* HCRYPTKEY */
	dwLegacyKeySpec uint32, /* DWORD */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	r, _, msg := nCryptTranslateHandleProc.Call(
		uintptr(unsafe.Pointer(phProvider)),
		uintptr(unsafe.Pointer(phKey)),
		uintptr(hLegacyProv),
		uintptr(hLegacyKey),
		uintptr(dwLegacyKeySpec),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptTranslateHandle() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptVerifyClaim(
	hSubjectKey uintptr, /* NCRYPT_KEY_HANDLE */
	hAuthorityKey uintptr, /* NCRYPT_KEY_HANDLE */
	dwClaimType uint32, /* DWORD */
	pParameterList *BcryptBufferDesc, /* NCryptBufferDesc* */
	pbClaimBlob *byte, /* PBYTE */
	cbClaimBlob uint32, /* DWORD */
	pOutput *BcryptBufferDesc, /* NCryptBufferDesc* */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	r, _, msg := nCryptVerifyClaimProc.Call(
		uintptr(hSubjectKey),
		uintptr(hAuthorityKey),
		uintptr(dwClaimType),
		uintptr(unsafe.Pointer(pParameterList)),
		uintptr(unsafe.Pointer(pbClaimBlob)),
		uintptr(cbClaimBlob),
		uintptr(unsafe.Pointer(pOutput)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptVerifyClaim() returned %X (%v)", r, msg)
	}

	return 0, nil
}

func NCryptVerifySignature(
	hKey uintptr, /* NCRYPT_KEY_HANDLE */
	pPaddingInfo unsafe.Pointer, /* VOID* */
	pbHashValue []byte, /* PBYTE */
	pbSignature []byte, /* PBYTE */
	dwFlags uint32, /* DWORD */
) (uint32, error) {

	r, _, msg := nCryptVerifySignatureProc.Call(
		uintptr(hKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&pbHashValue[0])),
		uintptr(len(pbHashValue)),
		uintptr(unsafe.Pointer(&pbSignature[0])),
		uintptr(len(pbSignature)),
		uintptr(dwFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		return uint32(r), fmt.Errorf("nCryptVerifySignature() returned %X (%v)", r, msg)
	}

	return 0, nil
}
