// Copyright (c) 2020-2023, El Mostafa IDRASSI.
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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRSAGenerateKey(t *testing.T) {

	testKeyLengths := []uint32{1024, 2048}
	testCases := []string{
		"NoName-NoPass", "NoName-PassUiCompatible", "NoName-PassNotUiCompatible",
		"Name-NoPass", "Name-PassUiCompatible", "Name-PassNotUiCompatible",
	}

	for _, testKeyLength := range testKeyLengths {
		for i, testCase := range testCases {
			testKeyName := ""
			testKeyPass := ""
			testIsUiCompatible := false
			if i >= 3 {
				keyUuidName, _ := uuid.NewRandom()
				testKeyName = keyUuidName.String()
			}
			if i == 1 || i == 2 || i == 4 || i == 5 {
				testKeyPass = "password123"
			}
			if i == 1 || i == 4 {
				testIsUiCompatible = true
			}
			t.Run(fmt.Sprintf("%d-%s", testKeyLength, testCase), func(t *testing.T) {
				testRSAGenerateAndFindKey(t, testKeyName, testKeyPass, testIsUiCompatible, testKeyLength, true)
			})
		}
	}
}

func TestRSASignPKCSWithPass(t *testing.T) {

	testKeyLengths := []uint32{1024, 2048}
	testCases := []string{
		"PassUiCompatible", "PassNotUiCompatible",
	}
	testHashes := map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		"SHA384": crypto.SHA384,
		"SHA512": crypto.SHA512,
	}
	testIsUiCompatible := false

	for _, testKeyLength := range testKeyLengths {
		for i, testCase := range testCases {
			if i == 0 {
				testIsUiCompatible = true
			}
			for testHashName, testHash := range testHashes {
				t.Run(fmt.Sprintf("%d-%s-%s", testKeyLength, testCase, testHashName), func(t *testing.T) {
					key, _ := GenerateRSAKey("", "password123", testIsUiCompatible, false, testKeyLength, 0, true)
					defer key.Delete()
					testRSASignDigestPKCS1v15(t, key, testHash)
				})
			}
		}
	}
}

func TestRSASignPSSWithPass(t *testing.T) {

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whatever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	testKeyLengths := []uint32{1024, 2048}
	testCases := []string{
		"PassUiCompatible", "PassNotUiCompatible",
	}
	testHashes := map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		//"SHA384": crypto.SHA384,
		//"SHA512": crypto.SHA512,
	}
	testSaltLengths := map[string]int{
		"SaltLengthAuto":       rsa.PSSSaltLengthAuto,
		"SaltLengthEqualsHash": rsa.PSSSaltLengthEqualsHash,
	}
	testIsUiCompatible := false

	for _, testKeyLength := range testKeyLengths {
		for i, testCase := range testCases {
			if i == 0 {
				testIsUiCompatible = true
			}
			for testHashName, testHash := range testHashes {
				for testSaltLengthName, testSaltLength := range testSaltLengths {
					t.Run(fmt.Sprintf("%d-%s-%s-%s", testKeyLength, testCase, testHashName, testSaltLengthName), func(t *testing.T) {
						key, _ := GenerateRSAKey("", "password123", testIsUiCompatible, false, testKeyLength, 0, true)
						defer key.Delete()
						testRSASignDigestPSS(t, key, testHash, testSaltLength)
					})
				}
			}
		}
	}
}

func TestRSASignPKCSWithoutPass(t *testing.T) {

	testKeyLengths := []uint32{1024, 2048}
	testHashes := map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		"SHA384": crypto.SHA384,
		"SHA512": crypto.SHA512,
	}

	for _, testKeyLength := range testKeyLengths {
		for testHashName, testHash := range testHashes {
			t.Run(fmt.Sprintf("%d-%s", testKeyLength, testHashName), func(t *testing.T) {
				key, _ := GenerateRSAKey("", "", false, false, testKeyLength, 0, true)
				defer key.Delete()
				testRSASignDigestPKCS1v15(t, key, testHash)
			})
		}
	}
}

func TestRSASignPSSWithoutPass(t *testing.T) {

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whatever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	testKeyLengths := []uint32{1024, 2048}
	testHashes := map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		//"SHA384": crypto.SHA384,
		//"SHA512": crypto.SHA512,
	}
	testSaltLengths := map[string]int{
		"SaltLengthAuto":       rsa.PSSSaltLengthAuto,
		"SaltLengthEqualsHash": rsa.PSSSaltLengthEqualsHash,
	}

	for _, testKeyLength := range testKeyLengths {
		for testHashName, testHash := range testHashes {
			for testSaltLengthName, testSaltLength := range testSaltLengths {
				t.Run(fmt.Sprintf("%d-%s-%s", testKeyLength, testHashName, testSaltLengthName), func(t *testing.T) {
					key, _ := GenerateRSAKey("", "", false, false, testKeyLength, 0, true)
					defer key.Delete()
					testRSASignDigestPSS(t, key, testHash, testSaltLength)
				})
			}
		}
	}
}

// This test prompts for the password using the Windows UI,
// therefore, it is commented out. Uncomment to test.
/*
func TestRSASignPKCSWithPassPrompt(t *testing.T) {

	testKeyLengths := []uint32{1024, 2048}
	testHashes := map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		"SHA384": crypto.SHA384,
		"SHA512": crypto.SHA512,
	}

	for _, testKeyLength := range testKeyLengths {
		for testHashName, testHash := range testHashes {
			t.Run(fmt.Sprintf("%d-%s", testKeyLength, testHashName), func(t *testing.T) {
				key, _ := GenerateRSAKey("", "password123", true, false, testKeyLength, 0, true)
				defer key.Delete()
				foundKey, _ := FindKey(key.Name(), "", true, false)
				testRSASignDigestPKCS1v15(t, foundKey, testHash)
			})
		}
	}
}
*/

// This test prompts for the password using the Windows UI,
// therefore, it is commented out. Uncomment to test.
/*
func TestRSASignPSSWithPassPrompt(t *testing.T) {

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whatever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	testKeyLengths := []uint32{1024, 2048}
	testHashes := map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		//"SHA384": crypto.SHA384,
		//"SHA512": crypto.SHA512,
	}
	testSaltLengths := map[string]int{
		"SaltLengthAuto":       rsa.PSSSaltLengthAuto,
		"SaltLengthEqualsHash": rsa.PSSSaltLengthEqualsHash,
	}

	for _, testKeyLength := range testKeyLengths {
		for testHashName, testHash := range testHashes {
			for testSaltLengthName, testSaltLength := range testSaltLengths {
				t.Run(fmt.Sprintf("%d-%s-%s", testKeyLength, testHashName, testSaltLengthName), func(t *testing.T) {
					key, _ := GenerateRSAKey("", "password123", true, false, testKeyLength, 0, true)
					defer key.Delete()
					foundKey, _ := FindKey(key.Name(), "", true, false)
					testRSASignDigestPSS(t, foundKey, testHash, testSaltLength)
				})
			}
		}
	}
}
*/

func testRSAGenerateAndFindKey(t *testing.T, name string, password string, isUICompatible bool, length uint32, toBeDeleted bool) {

	// Generate key
	key, err := GenerateRSAKey(name, password, isUICompatible, false, length, 0, true)
	require.NoError(t, err)
	require.NotNil(t, key)
	if toBeDeleted {
		defer func() {
			require.NoError(t, key.Delete())
		}()
	}
	require.Equal(t, key.Size(), (length+7)/8)

	// Find the key
	keyBis, err := FindKey(key.Name(), password, isUICompatible, false)
	require.NoError(t, err)
	require.NotNil(t, keyBis)
	require.Equal(t, key.Name(), keyBis.Name())
	require.Equal(t, key.Size(), keyBis.Size())
	require.Equal(t, key.Public(), keyBis.Public())
}

func testRSASignDigestPSS(t *testing.T, key crypto.Signer, hash crypto.Hash, saltLength int) {
	input := []byte("test string for rsa signature")

	// Create digest
	h := hash.New()
	_, err := h.Write(input)
	require.NoError(t, err)
	digest := h.Sum(nil)

	// Sign digest
	pssOptions := &rsa.PSSOptions{
		SaltLength: saltLength,
		Hash:       hash,
	}
	sig, err := key.Sign(rand.Reader, digest, pssOptions)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify
	rsaPubkey := key.Public().(*rsa.PublicKey)
	err = rsa.VerifyPSS(rsaPubkey, hash, digest, sig, pssOptions)
	require.NoError(t, err)
}

func testRSASignDigestPKCS1v15(t *testing.T, key crypto.Signer, hash crypto.Hash) {
	input := []byte("test string for rsa signature")

	// Create digest
	h := hash.New()
	_, err := h.Write(input)
	require.NoError(t, err)
	digest := h.Sum(nil)

	// Sign digest
	sig, err := key.Sign(rand.Reader, digest, hash)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify
	rsaPubkey := key.Public().(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(rsaPubkey, hash, digest, sig)
	require.NoError(t, err)
}
