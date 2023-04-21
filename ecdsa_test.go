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
	"fmt"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestECDSAGenerateKey(t *testing.T) {

	testCases := []string{
		"NoName-NoPass", "NoName-PassUiCompatible", "NoName-PassNotUiCompatible",
		"Name-NoPass", "Name-PassUiCompatible", "Name-PassNotUiCompatible",
	}

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
		t.Run(fmt.Sprintf("P256-%s", testCase), func(t *testing.T) {
			testECDSAGenerateAndFindKey(t, testKeyName, testKeyPass, testIsUiCompatible, elliptic.P256(), true)
		})
	}
}

// Signing SHA384 and SHA512 with P256 key returns TPM_20_E_SIZE.
func TestECDSASignWithPass(t *testing.T) {

	testCases := []string{
		"PassUiCompatible", "PassNotUiCompatible",
	}
	testHashes := map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		//"SHA384": crypto.SHA384,
		//"SHA512": crypto.SHA512,
	}
	testIsUiCompatible := false

	for i, testCase := range testCases {
		if i == 0 {
			testIsUiCompatible = true
		}
		for testHashName, testHash := range testHashes {
			t.Run(fmt.Sprintf("P256-%s-%s", testCase, testHashName), func(t *testing.T) {
				key, _ := GenerateECDSAKey("", "password123", testIsUiCompatible, false, elliptic.P256(), 0, true)
				defer key.Delete()
				testECDSASignDigest(t, key, testHash)
			})
		}
	}
}

// Signing SHA384 and SHA512 with P256 key returns TPM_20_E_SIZE.
func TestECDSASignWithoutPass(t *testing.T) {

	testHashes := map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		//"SHA384": crypto.SHA384,
		//"SHA512": crypto.SHA512,
	}

	for testHashName, testHash := range testHashes {
		t.Run(fmt.Sprintf("P256-%s", testHashName), func(t *testing.T) {
			key, _ := GenerateECDSAKey("", "", false, false, elliptic.P256(), 0, true)
			defer key.Delete()
			testECDSASignDigest(t, key, testHash)
		})
	}
}

// Signing SHA384 and SHA512 with P256 key returns TPM_20_E_SIZE.
// This test prompts for the password using the Windows UI,
// therefore, it is commented out. Uncomment to test.
/*
func TestECDSASignWithPassPrompt(t *testing.T) {
	testHashes := map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		//"SHA384": crypto.SHA384,
		//"SHA512": crypto.SHA512,
	}

	for testHashName, testHash := range testHashes {
		t.Run(fmt.Sprintf("P256-%s", testHashName), func(t *testing.T) {
			key, _ := GenerateECDSAKey("", "password123", true, false, elliptic.P256(), 0, true)
			defer key.Delete()
			foundKey, _ := FindKey(key.Name(), "", true, false)
			testECDSASignDigest(t, foundKey, testHash)
		})
	}
}
*/

func testECDSAGenerateAndFindKey(t *testing.T, name string, password string, isUICompatible bool, curve elliptic.Curve, toBeDeleted bool) {

	// Generate key
	key, err := GenerateECDSAKey(name, password, isUICompatible, false, curve, 0, true)
	require.NoError(t, err)
	require.NotNil(t, key)
	if toBeDeleted {
		defer func() {
			require.NoError(t, key.Delete())
		}()
	}
	require.Equal(t, key.Size(), uint32((curve.Params().BitSize+7)/8))

	// Find the key
	keyBis, err := FindKey(key.Name(), password, isUICompatible, false)
	require.NoError(t, err)
	require.NotNil(t, keyBis)
	require.Equal(t, key.Name(), keyBis.Name())
	require.Equal(t, key.Size(), keyBis.Size())
	require.Equal(t, key.Public(), keyBis.Public())
}

func testECDSASignDigest(t *testing.T, key crypto.Signer, hash crypto.Hash) {
	input := []byte("test string for ecdsa signature")

	// Create digest
	h := hash.New()
	_, err := h.Write(input)
	require.NoError(t, err)
	digest := h.Sum(nil)

	// Sign digest
	sig, err := key.Sign(rand.Reader, digest, hash)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify signature
	ecdsaPubkey := key.Public().(*ecdsa.PublicKey)
	isVerified := ecdsa.VerifyASN1(ecdsaPubkey, digest, sig)
	require.Equal(t, isVerified, true)
}
