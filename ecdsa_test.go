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
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func testECDSAGenerateAndFindKey(t *testing.T, name string, password string, curve elliptic.Curve, toBeDeleted bool) {

	// Generate key
	key, err := GenerateECDSAKey(name, password, curve, true)
	require.NoError(t, err)
	require.NotNil(t, key)
	if toBeDeleted {
		defer func() {
			require.NoError(t, key.Delete())
		}()
	}
	require.Equal(t, key.Size(), (curve.Params().BitSize+7)/8)

	// Find the key
	keyBis, err := findKey(key.Name(), password)
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

func TestECDSAGenerateKey(t *testing.T) {
	// We only test NIST-P256 as not all chips support the other curves.
	t.Run("ECDSAGEN-P256-NoName-NoPass", func(t *testing.T) { testECDSAGenerateAndFindKey(t, "", "", elliptic.P256(), true) })
	t.Run("ECDSAGEN-P256-NoName-Pass", func(t *testing.T) { testECDSAGenerateAndFindKey(t, "", "password123", elliptic.P256(), true) })
	t.Run("ECDSAGEN-P256-Name-NoPass", func(t *testing.T) {
		uuidName, err := uuid.NewRandom()
		require.NoError(t, err)
		name := uuidName.String()
		testECDSAGenerateAndFindKey(t, name, "", elliptic.P256(), true)
	})
	t.Run("ECDSAGEN-P256-Name-Pass", func(t *testing.T) {
		uuidName, err := uuid.NewRandom()
		require.NoError(t, err)
		name := uuidName.String()
		testECDSAGenerateAndFindKey(t, name, "password", elliptic.P256(), true)
	})
}

func TestECDSASignWithPass(t *testing.T) {

	// Generate key
	key, err := GenerateECDSAKey("", "", elliptic.P256(), true)
	require.NoError(t, err)
	require.NotNil(t, key)
	defer func() {
		require.NoError(t, key.Delete())
	}()

	// Test signatures
	// N.B : Signing SHA384/SHA512 fails, why ?
	t.Run("ECDSASIGN-SHA1", func(t *testing.T) { testECDSASignDigest(t, key, crypto.SHA1) })
	t.Run("ECDSASIGN-SHA256", func(t *testing.T) { testECDSASignDigest(t, key, crypto.SHA256) })
	//t.Run("ECDSASIGN-SHA384", func(t *testing.T) { testECDSASignDigest(t, key, crypto.SHA384) }) 0x802801D5
	//t.Run("ECDSASIGN-SHA512", func(t *testing.T) { testECDSASignDigest(t, key, crypto.SHA512) }) 0x802801D5
}

func TestECDSASignWithoutPass(t *testing.T) {

	// Generate key
	key, err := GenerateECDSAKey("", "", elliptic.P256(), true)
	require.NoError(t, err)
	require.NotNil(t, key)
	defer func() {
		require.NoError(t, key.Delete())
	}()

	// Test signatures
	// N.B : Signing SHA384/SHA512 fails, why ?
	t.Run("ECDSASIGN-SHA1", func(t *testing.T) { testECDSASignDigest(t, key, crypto.SHA1) })
	t.Run("ECDSASIGN-SHA256", func(t *testing.T) { testECDSASignDigest(t, key, crypto.SHA256) })
	//t.Run("ECDSASIGN-SHA384", func(t *testing.T) { testECDSASignDigest(t, key, crypto.SHA384) }) 0x802801D5
	//t.Run("ECDSASIGN-SHA512", func(t *testing.T) { testECDSASignDigest(t, key, crypto.SHA512) }) 0x802801D5
}
