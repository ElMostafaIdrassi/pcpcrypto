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
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"github.com/ElMostafaIdrassi/goncrypt"
	"github.com/google/go-tpm/legacy/tpm2"
	"golang.org/x/sys/windows"
)

type KeyUsage uint32

const (
	KeyUsageDefault           KeyUsage = 0x00000000
	KeyUsageAllowDecrypt      KeyUsage = 0x00000001 // NcryptAllowDecryptFlag
	KeyUsageAllowSigning      KeyUsage = 0x00000002 // NcryptAllowSigningFlag
	KeyUsageAllowKeyAgreement KeyUsage = 0x00000004 // NcryptAllowKeyAgreementFlag
	KeyUsageAllowAllUsages    KeyUsage = 0x00ffffff // NcryptAllowAllUsages
)

func (u *KeyUsage) fromNcryptFlag(flag goncrypt.NcryptKeyUsagePropertyFlag) {
	*u = KeyUsageDefault
	if flag&goncrypt.NcryptAllowDecryptFlag != 0 {
		*u |= KeyUsageAllowDecrypt
	}
	if flag&goncrypt.NcryptAllowSigningFlag != 0 {
		*u |= KeyUsageAllowSigning
	}
	if flag&goncrypt.NcryptAllowKeyAgreementFlag != 0 {
		*u |= KeyUsageAllowKeyAgreement
	}
	if flag&goncrypt.NcryptAllowAllUsages != 0 {
		*u |= KeyUsageAllowAllUsages
	}
}

func (u *KeyUsage) Value() uint32 {
	return uint32(*u)
}

type UIPolicy uint32

const (
	UIPolicyNoConsent                       UIPolicy = 0x00000000
	UIPolicyConsentWithOptionalPIN          UIPolicy = 0x00000001
	UIPolicyConsentWithMandatoryPIN         UIPolicy = 0x00000002
	UIPolicyConsentWithMandatoryFingerprint UIPolicy = 0x00000004
)

func (p *UIPolicy) fromNcryptFlag(flag goncrypt.NcryptUiPolicyPropertyFlag) {
	*p = UIPolicyNoConsent
	if flag == goncrypt.NcryptUiProtectKeyFlag {
		*p = UIPolicyConsentWithOptionalPIN
	} else if flag == goncrypt.NcryptUiForceHighProtectionFlag {
		*p = UIPolicyConsentWithMandatoryPIN
	} else if flag == goncrypt.NcryptUiFingerprintProtectionFlag {
		*p = UIPolicyConsentWithMandatoryFingerprint
	}
}

func (p *UIPolicy) Value() uint32 {
	return uint32(*p)
}

// utf16BytesToString transforms a []byte which contains a wide char string in LE
// into its []uint16 corresponding representation,
// then returns the UTF-8 encoding of the UTF-16 sequence,
// with a terminating NUL removed. If after converting the []byte into
// a []uint16, there is a NUL uint16, the conversion to string stops
// at that NUL uint16.
func utf16BytesToString(buf []byte) (string, error) {

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

// stringToUtf16Bytes returns the UTF-16 encoding of the UTF-8 string
// str, as a byte array with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func stringToUtf16Bytes(str string) ([]byte, error) {
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

// See https://github.com/microsoft/TSS.MSR/blob/main/PCPTool.v11/inc/TpmAtt.h

const BcryptPcpKeyMagic uint32 = 0x4D504350 // PCPM
const PCPTypeTpm12 uint32 = 0x00000001
const PCPTypeTpm20 uint32 = 0x00000002

type PCPKeyBlobWin8Header struct {
	Magic                  uint32
	HeaderLength           uint32
	PCPType                uint32
	Flags                  uint32
	PublicLength           uint32
	PrivateLength          uint32
	MigrationPublicLength  uint32
	MigrationPrivateLength uint32
	PolicyDigestListLength uint32
	PCRBindingLength       uint32
	PCRDigestLength        uint32
	EncryptedSecretLength  uint32
	Tpm12HostageBlobLength uint32
}

type PCPKeyBlobWin8 struct {
	PCPKeyBlobWin8Header PCPKeyBlobWin8Header
	Public               []byte // TPM2B_PUBLIC
	Private              []byte // TPM2B_PRIVATE
	MigrationPublic      []byte
	MigrationPrivate     []byte
	PolicyDigestList     []byte // TPML_DIGEST
	PCRBinding           []byte
	PCRDigest            []byte
	EncryptedSecret      []byte
	Tpm12HostageBlob     []byte
}

func (k *PCPKeyBlobWin8) fromBlobData(blobData []byte) error {
	if len(blobData) > int(unsafe.Sizeof(k.PCPKeyBlobWin8Header)) &&
		binary.LittleEndian.Uint32(blobData[4:8]) == uint32(unsafe.Sizeof(k.PCPKeyBlobWin8Header)) {
		pcpKeyBlobWin8Header := *(*PCPKeyBlobWin8Header)(unsafe.Pointer(&blobData[0]))
		blobDataExpectedLength := uint32(unsafe.Sizeof(pcpKeyBlobWin8Header)) +
			pcpKeyBlobWin8Header.PublicLength +
			pcpKeyBlobWin8Header.PrivateLength +
			pcpKeyBlobWin8Header.MigrationPublicLength +
			pcpKeyBlobWin8Header.MigrationPrivateLength +
			pcpKeyBlobWin8Header.PolicyDigestListLength +
			pcpKeyBlobWin8Header.PCRBindingLength +
			pcpKeyBlobWin8Header.PCRDigestLength +
			pcpKeyBlobWin8Header.EncryptedSecretLength +
			pcpKeyBlobWin8Header.Tpm12HostageBlobLength
		if uint32(len(blobData)) == blobDataExpectedLength {
			k.PCPKeyBlobWin8Header = pcpKeyBlobWin8Header

			currentDataPosition := uint32(unsafe.Sizeof(k.PCPKeyBlobWin8Header))
			k.Public = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobWin8Header.PublicLength]

			currentDataPosition += k.PCPKeyBlobWin8Header.PublicLength
			k.Private = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobWin8Header.PrivateLength]

			currentDataPosition += k.PCPKeyBlobWin8Header.PrivateLength
			k.MigrationPublic = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobWin8Header.MigrationPublicLength]

			currentDataPosition += k.PCPKeyBlobWin8Header.MigrationPublicLength
			k.MigrationPrivate = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobWin8Header.MigrationPrivateLength]

			currentDataPosition += k.PCPKeyBlobWin8Header.MigrationPrivateLength
			k.PolicyDigestList = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobWin8Header.PolicyDigestListLength]

			currentDataPosition += k.PCPKeyBlobWin8Header.PolicyDigestListLength
			k.PCRBinding = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobWin8Header.PCRBindingLength]

			currentDataPosition += k.PCPKeyBlobWin8Header.PCRBindingLength
			k.PCRDigest = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobWin8Header.PCRDigestLength]

			currentDataPosition += k.PCPKeyBlobWin8Header.PCRDigestLength
			k.EncryptedSecret = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobWin8Header.EncryptedSecretLength]

			currentDataPosition += k.PCPKeyBlobWin8Header.EncryptedSecretLength
			k.Tpm12HostageBlob = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobWin8Header.Tpm12HostageBlobLength]

			return nil
		} else {
			return fmt.Errorf("invalid PCP Key Blob (expected blob length %d, got %d)", blobDataExpectedLength, len(blobData))
		}
	} else {
		return fmt.Errorf("invalid PCP Key Blob (expected header length %d, got %d)", unsafe.Sizeof(k.PCPKeyBlobWin8Header), len(blobData))
	}
}

type PCP20KeyBlobHeader struct {
	Magic                  uint32
	HeaderLength           uint32
	PCPType                uint32
	Flags                  uint32
	PublicLength           uint32
	PrivateLength          uint32
	MigrationPublicLength  uint32
	MigrationPrivateLength uint32
	PolicyDigestListLength uint32
	PCRBindingLength       uint32
	PCRDigestLength        uint32
	EncryptedSecretLength  uint32
	Tpm12HostageBlobLength uint32
	PCRAlgId               uint16
}

type PCP20KeyBlob struct {
	PCP20KeyBlobHeader PCP20KeyBlobHeader
	Public             []byte // TPM2B_PUBLIC
	Private            []byte // TPM2B_PRIVATE
	MigrationPublic    []byte
	MigrationPrivate   []byte
	PolicyDigestList   []byte // TPML_DIGEST
	PCRBinding         []byte
	PCRDigest          []byte
	EncryptedSecret    []byte
	Tpm12HostageBlob   []byte
}

func (k *PCP20KeyBlob) fromBlobData(blobData []byte) error {
	if len(blobData) > int(unsafe.Sizeof(k.PCP20KeyBlobHeader)) &&
		binary.LittleEndian.Uint32(blobData[4:8]) == uint32(unsafe.Sizeof(k.PCP20KeyBlobHeader)) {
		pcp20KeyBlobHeader := *(*PCP20KeyBlobHeader)(unsafe.Pointer(&blobData[0]))
		blobDataExpectedLength := uint32(unsafe.Sizeof(pcp20KeyBlobHeader)) +
			pcp20KeyBlobHeader.PublicLength +
			pcp20KeyBlobHeader.PrivateLength +
			pcp20KeyBlobHeader.MigrationPublicLength +
			pcp20KeyBlobHeader.MigrationPrivateLength +
			pcp20KeyBlobHeader.PolicyDigestListLength +
			pcp20KeyBlobHeader.PCRBindingLength +
			pcp20KeyBlobHeader.PCRDigestLength +
			pcp20KeyBlobHeader.EncryptedSecretLength +
			pcp20KeyBlobHeader.Tpm12HostageBlobLength
		if uint32(len(blobData)) == blobDataExpectedLength {
			k.PCP20KeyBlobHeader = pcp20KeyBlobHeader

			currentDataPosition := uint32(unsafe.Sizeof(k.PCP20KeyBlobHeader))
			k.Public = blobData[currentDataPosition : currentDataPosition+k.PCP20KeyBlobHeader.PublicLength]

			currentDataPosition += k.PCP20KeyBlobHeader.PublicLength
			k.Private = blobData[currentDataPosition : currentDataPosition+k.PCP20KeyBlobHeader.PrivateLength]

			currentDataPosition += k.PCP20KeyBlobHeader.PrivateLength
			k.MigrationPublic = blobData[currentDataPosition : currentDataPosition+k.PCP20KeyBlobHeader.MigrationPublicLength]

			currentDataPosition += k.PCP20KeyBlobHeader.MigrationPublicLength
			k.MigrationPrivate = blobData[currentDataPosition : currentDataPosition+k.PCP20KeyBlobHeader.MigrationPrivateLength]

			currentDataPosition += k.PCP20KeyBlobHeader.MigrationPrivateLength
			k.PolicyDigestList = blobData[currentDataPosition : currentDataPosition+k.PCP20KeyBlobHeader.PolicyDigestListLength]

			currentDataPosition += k.PCP20KeyBlobHeader.PolicyDigestListLength
			k.PCRBinding = blobData[currentDataPosition : currentDataPosition+k.PCP20KeyBlobHeader.PCRBindingLength]

			currentDataPosition += k.PCP20KeyBlobHeader.PCRBindingLength
			k.PCRDigest = blobData[currentDataPosition : currentDataPosition+k.PCP20KeyBlobHeader.PCRDigestLength]

			currentDataPosition += k.PCP20KeyBlobHeader.PCRDigestLength
			k.EncryptedSecret = blobData[currentDataPosition : currentDataPosition+k.PCP20KeyBlobHeader.EncryptedSecretLength]

			currentDataPosition += k.PCP20KeyBlobHeader.EncryptedSecretLength
			k.Tpm12HostageBlob = blobData[currentDataPosition : currentDataPosition+k.PCP20KeyBlobHeader.Tpm12HostageBlobLength]

			return nil
		} else {
			return fmt.Errorf("invalid PCP Key Blob (expected blob length %d, got %d)", blobDataExpectedLength, len(blobData))
		}
	} else {
		return fmt.Errorf("invalid PCP Key Blob (expected header length %d, got %d)", unsafe.Sizeof(k.PCP20KeyBlobHeader), len(blobData))
	}
}

type PCPKeyBlobHeader struct {
	Magic        uint32
	HeaderLength uint32
	PCPType      uint32
	Flags        uint32
	TPKKeyLength uint32
}

type PCPKeyBlob struct {
	PCPKeyBlobHeader PCPKeyBlobHeader
	TPMKey           []byte
}

func (k *PCPKeyBlob) fromBlobData(blobData []byte) error {
	if len(blobData) > int(unsafe.Sizeof(k.PCPKeyBlobHeader)) &&
		binary.LittleEndian.Uint32(blobData[4:8]) == uint32(unsafe.Sizeof(k.PCPKeyBlobHeader)) {
		pcpKeyBlobHeader := *(*PCPKeyBlobHeader)(unsafe.Pointer(&blobData[0]))
		blobDataExpectedLength := uint32(unsafe.Sizeof(pcpKeyBlobHeader)) + pcpKeyBlobHeader.TPKKeyLength
		if uint32(len(blobData)) == blobDataExpectedLength {
			k.PCPKeyBlobHeader = pcpKeyBlobHeader
			currentDataPosition := uint32(unsafe.Sizeof(k.PCPKeyBlobHeader))
			k.TPMKey = blobData[currentDataPosition : currentDataPosition+k.PCPKeyBlobHeader.TPKKeyLength]
			return nil
		} else {
			return fmt.Errorf("invalid PCP 2.0 Key Blob (expected blob length %d, got %d)", blobDataExpectedLength, len(blobData))
		}
	} else {
		return fmt.Errorf("invalid PCP 2.0 Key Blob (expected header length %d, got %d)", unsafe.Sizeof(k.PCPKeyBlobHeader), len(blobData))
	}
}

type TlvRecord struct {
	Tag   uint32
	Len   uint32
	Value []byte
}

func GetPCPKeyFileTLVRecords(pcpKeyFilePath string) ([]TlvRecord, error) {
	// Read the file into a byte array
	data, err := os.ReadFile(pcpKeyFilePath)
	if err != nil {
		return nil, err
	}

	// Check that the PCP Key File is at least 8 bytes long.
	if len(data) <= 8 {
		return nil, fmt.Errorf("invalid PCP Key File (too short)")
	}

	// Check that the PCP Key File starts with "PKSP" and ends with "PKSP".
	if !bytes.HasPrefix(data, []byte("PKSP")) || !bytes.HasSuffix(data, []byte("PKSP")) {
		return nil, fmt.Errorf("invalid PCP Key File (missing header or footer)")
	}

	// Move the data past the "PKSP" header and before the "PKSP" footer.
	data = data[4 : len(data)-4]

	// Decode the PCP Key File data as a list of TLV records.
	var tlvRecords []TlvRecord
	for len(data) > 0 {
		if len(data) < 8 {
			return nil, fmt.Errorf("invalid PCP Key File (too short)")
		}
		tag := binary.LittleEndian.Uint32(data[0:4])
		length := binary.LittleEndian.Uint32(data[4:8])
		if uint32(len(data)) < length+8 {
			return nil, fmt.Errorf("invalid PCP Key File (too short)")
		}
		value := data[8 : length+8]
		tlvRecords = append(tlvRecords, TlvRecord{tag, length, value})
		data = data[length+8:]
	}

	return tlvRecords, nil
}

func ParsePCPKeyFile(pcpKeyFilePath string) (
	public *tpm2.Public,
	private []byte,
	policyDigest *tpm2.TPMLDigest,
	keyName string,
	keyAlgorithm string,
	err error,
) {
	var tlvRecords []TlvRecord
	var blobData []byte
	var pcpKeyBlobWin8 PCPKeyBlobWin8
	var pcp20KeyBlob PCP20KeyBlob
	var tpm2Public tpm2.Public

	tlvRecords, err = GetPCPKeyFileTLVRecords(pcpKeyFilePath)
	if err != nil {
		return
	}

	for _, tlvRecord := range tlvRecords {
		if tlvRecord.Tag == 0x02000000 {
			keyName, err = utf16BytesToString(tlvRecord.Value)
			if err != nil {
				return
			}
		} else if tlvRecord.Tag == 0x02000004 {
			keyAlgorithm, err = utf16BytesToString(tlvRecord.Value)
			if err != nil {
				return
			}
		} else if tlvRecord.Tag == 0x01000002 || tlvRecord.Tag == 0x01000003 {
			blobData = tlvRecord.Value
			if tlvRecord.Tag == 0x01000003 {
				inDataBlob := &windows.DataBlob{
					Data: &blobData[0],
					Size: uint32(len(blobData)),
				}
				outDataBllob := &windows.DataBlob{}

				err = windows.CryptUnprotectData(inDataBlob, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, outDataBllob)
				if err != nil {
					return
				}
				defer windows.LocalFree(windows.Handle(unsafe.Pointer(outDataBllob.Data)))

				blobData = make([]byte, outDataBllob.Size)
				copy(blobData, unsafe.Slice(outDataBllob.Data, outDataBllob.Size))
			}

			if len(blobData) <= 8 {
				err = fmt.Errorf("invalid PCP Key File (too short)")
				return
			}

			if binary.LittleEndian.Uint32(blobData[0:4]) != BcryptPcpKeyMagic {
				err = fmt.Errorf("invalid PCP Key File (invalid magic, expected 0x%08x, got 0x%08x)", BcryptPcpKeyMagic, binary.LittleEndian.Uint32(blobData[0:4]))
				return
			}

			if binary.LittleEndian.Uint32(blobData[4:8]) == uint32(unsafe.Sizeof(PCPKeyBlob{}.PCPKeyBlobHeader)) {
				err = fmt.Errorf("invalid PCP Key File (unsupported PCP 1.2 Key Blob version)")
				return
			} else if binary.LittleEndian.Uint32(blobData[4:8]) == uint32(unsafe.Sizeof(pcpKeyBlobWin8.PCPKeyBlobWin8Header)) {
				err = pcpKeyBlobWin8.fromBlobData(blobData)
				if err != nil {
					return
				}
				// pcpKeyBlobWin8.Public is a TPM2B_PUBLIC structure, which is a UINT16 size followed by a TPMT_PUBLIC structure.
				// We need to strip the UINT16 size from the beginning of the blob before we can decode the TPMT_PUBLIC structure.
				if len(pcpKeyBlobWin8.Public) < 2 {
					err = fmt.Errorf("invalid PCP Key File (public key blob too short)")
					return
				}
				tpm2Public, err = tpm2.DecodePublic(pcpKeyBlobWin8.Public[2:])
				if err != nil {
					return
				}
				public = &tpm2Public
				policyDigest, err = tpm2.DecodeTPMLDigest(pcpKeyBlobWin8.PolicyDigestList)
				if err != nil {
					return
				}
				if len(pcpKeyBlobWin8.Private) < 2 {
					err = fmt.Errorf("invalid PCP Key File (private key blob too short)")
					return
				}
				private = pcpKeyBlobWin8.Private
			} else if binary.LittleEndian.Uint32(blobData[4:8]) == uint32(unsafe.Sizeof(pcp20KeyBlob.PCP20KeyBlobHeader)) {
				err = pcp20KeyBlob.fromBlobData(blobData)
				if err != nil {
					return
				}
				// pcp20KeyBlob.Public is a TPM2B_PUBLIC structure, which is a UINT16 size followed by a TPMT_PUBLIC structure.
				// We need to strip the UINT16 size from the beginning of the blob before we can decode the TPMT_PUBLIC structure.
				if len(pcp20KeyBlob.Public) < 2 {
					err = fmt.Errorf("invalid PCP Key File (public key blob too short)")
					return
				}
				tpm2Public, err = tpm2.DecodePublic(pcp20KeyBlob.Public[2:])
				policyDigest, err = tpm2.DecodeTPMLDigest(pcp20KeyBlob.PolicyDigestList)
				if err != nil {
					return
				}
				public = &tpm2Public
				if len(pcp20KeyBlob.Private) < 2 {
					err = fmt.Errorf("invalid PCP Key File (private key blob too short)")
					return
				}
				private = pcp20KeyBlob.Private
			} else {
				err = fmt.Errorf("invalid PCP Key File (invalid blob header size)")
				return
			}

			break
		}
	}

	return
}
