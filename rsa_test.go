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
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

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

func TestRSAGenerateKey(t *testing.T) {
	t.Run("RSAGEN-1024-NoName-NoPass", func(t *testing.T) { testRSAGenerateAndFindKey(t, "", "", false, 1024, true) })
	t.Run("RSAGEN-1024-Name-NoPass", func(t *testing.T) {
		uuidName, err := uuid.NewRandom()
		require.NoError(t, err)
		name := uuidName.String()
		testRSAGenerateAndFindKey(t, name, "", false, 1024, true)
	})
	t.Run("RSAGEN-1024-NoName-Pass-NotUICompatible", func(t *testing.T) { testRSAGenerateAndFindKey(t, "", "password123", false, 1024, true) })
	t.Run("RSAGEN-1024-Name-Pass-NotUICompatible", func(t *testing.T) {
		uuidName, err := uuid.NewRandom()
		require.NoError(t, err)
		name := uuidName.String()
		testRSAGenerateAndFindKey(t, name, "password123", false, 1024, true)
	})
	t.Run("RSAGEN-1024-NoName-Pass-UICompatible", func(t *testing.T) { testRSAGenerateAndFindKey(t, "", "password123", true, 1024, true) })
	t.Run("RSAGEN-1024-Name-Pass-UICompatible", func(t *testing.T) {
		uuidName, err := uuid.NewRandom()
		require.NoError(t, err)
		name := uuidName.String()
		testRSAGenerateAndFindKey(t, name, "password123", true, 1024, true)
	})

	t.Run("RSAGEN-2048-NoName-NoPass", func(t *testing.T) { testRSAGenerateAndFindKey(t, "", "", false, 2048, true) })
	t.Run("RSAGEN-2048-Name-NoPass", func(t *testing.T) {
		uuidName, err := uuid.NewRandom()
		require.NoError(t, err)
		name := uuidName.String()
		testRSAGenerateAndFindKey(t, name, "", false, 2048, true)
	})
	t.Run("RSAGEN-2048-NoName-Pass-NotUICompatible", func(t *testing.T) { testRSAGenerateAndFindKey(t, "", "password123", false, 2048, true) })
	t.Run("RSAGEN-2048-Name-Pass-NotUICompatible", func(t *testing.T) {
		uuidName, err := uuid.NewRandom()
		require.NoError(t, err)
		name := uuidName.String()
		testRSAGenerateAndFindKey(t, name, "password123", false, 2048, true)
	})
	t.Run("RSAGEN-2048-NoName-Pass-UICompatible", func(t *testing.T) { testRSAGenerateAndFindKey(t, "", "password123", true, 2048, true) })
	t.Run("RSAGEN-2048-Name-Pass-UICompatible", func(t *testing.T) {
		uuidName, err := uuid.NewRandom()
		require.NoError(t, err)
		name := uuidName.String()
		testRSAGenerateAndFindKey(t, name, "password123", true, 2048, true)
	})
}

func TestRSASignWithPassNotUICompatible(t *testing.T) {

	// Generate key
	key1024, err := GenerateRSAKey("", "password123", false, false, 1024, 0, true)
	require.NoError(t, err)
	require.NotNil(t, key1024)
	defer func() {
		require.NoError(t, key1024.Delete())
	}()

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whetever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA1, rsa.PSSSaltLengthEqualsHash) })     // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA256, rsa.PSSSaltLengthEqualsHash) }) // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	//t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA384, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA512, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPSS-1024-SALTAUTO-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA1, rsa.PSSSaltLengthAuto) })
	t.Run("RSASIGNPSS-1024-SALTAUTO-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA256, rsa.PSSSaltLengthAuto) })
	//t.Run("RSASIGNPSS-1024-SALTAUTO-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA384, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-1024-SALTAUTO-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA512, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPKCS-1024-SHA1", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA1) })
	t.Run("RSASIGNPKCS-1024-SHA256", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA256) })
	t.Run("RSASIGNPKCS-1024-SHA384", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA384) })
	t.Run("RSASIGNPKCS-1024-SHA512", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA512) })

	// Generate key
	key2048, err := GenerateRSAKey("", "password123", false, false, 2048, 0, true)
	require.NoError(t, err)
	require.NotNil(t, key2048)
	defer func() {
		require.NoError(t, key2048.Delete())
	}()

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whetever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA1, rsa.PSSSaltLengthEqualsHash) })     // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA256, rsa.PSSSaltLengthEqualsHash) }) // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	//t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA384, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA512, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPSS-2048-SALTAUTO-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA1, rsa.PSSSaltLengthAuto) })
	t.Run("RSASIGNPSS-2048-SALTAUTO-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA256, rsa.PSSSaltLengthAuto) })
	//t.Run("RSASIGNPSS-2048-SALTAUTO-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA384, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-2048-SALTAUTO-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA512, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPKCS-2048-SHA1", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA1) })
	t.Run("RSASIGNPKCS-2048-SHA256", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA256) })
	t.Run("RSASIGNPKCS-2048-SHA384", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA384) })
	t.Run("RSASIGNPKCS-2048-SHA512", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA512) })
}

func TestRSASignWithPassUICompatible(t *testing.T) {

	// Generate key
	key1024, err := GenerateRSAKey("", "password123", true, false, 1024, 0, true)
	require.NoError(t, err)
	require.NotNil(t, key1024)
	defer func() {
		require.NoError(t, key1024.Delete())
	}()

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whetever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA1, rsa.PSSSaltLengthEqualsHash) })     // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA256, rsa.PSSSaltLengthEqualsHash) }) // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	//t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA384, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA512, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPSS-1024-SALTAUTO-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA1, rsa.PSSSaltLengthAuto) })
	t.Run("RSASIGNPSS-1024-SALTAUTO-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA256, rsa.PSSSaltLengthAuto) })
	//t.Run("RSASIGNPSS-1024-SALTAUTO-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA384, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-1024-SALTAUTO-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA512, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPKCS-1024-SHA1", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA1) })
	t.Run("RSASIGNPKCS-1024-SHA256", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA256) })
	t.Run("RSASIGNPKCS-1024-SHA384", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA384) })
	t.Run("RSASIGNPKCS-1024-SHA512", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA512) })

	// Generate key
	key2048, err := GenerateRSAKey("", "password123", true, false, 2048, 0, true)
	require.NoError(t, err)
	require.NotNil(t, key2048)
	defer func() {
		require.NoError(t, key2048.Delete())
	}()

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whetever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA1, rsa.PSSSaltLengthEqualsHash) })     // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA256, rsa.PSSSaltLengthEqualsHash) }) // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	//t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA384, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA512, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPSS-2048-SALTAUTO-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA1, rsa.PSSSaltLengthAuto) })
	t.Run("RSASIGNPSS-2048-SALTAUTO-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA256, rsa.PSSSaltLengthAuto) })
	//t.Run("RSASIGNPSS-2048-SALTAUTO-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA384, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-2048-SALTAUTO-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA512, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPKCS-2048-SHA1", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA1) })
	t.Run("RSASIGNPKCS-2048-SHA256", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA256) })
	t.Run("RSASIGNPKCS-2048-SHA384", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA384) })
	t.Run("RSASIGNPKCS-2048-SHA512", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA512) })
}

/*
// This test prompts for the password using the Windows UI,
// therefore, it is commented out. Uncomment to test.
func TestRSASignWithPassUICompatiblePrompt(t *testing.T) {

	// Generate key
	key1024Gen, err := GenerateRSAKey("", "password123", true, 1024, 0, true)
	require.NoError(t, err)
	require.NotNil(t, key1024Gen)
	defer func() {
		require.NoError(t, key1024Gen.Delete())
	}()
	key1024, err := FindKey(key1024Gen.Name(), "", true)
	require.NoError(t, err)
	require.NotNil(t, key1024)

	// Because these tests run in parallel, we need this hack
	// to run them one at a time. This is to avoid triggering
	// TPM's dictionary attack lockout and requiring us to
	// reboot the machine.
	awaitElement := sync.WaitGroup{}
	awaitElement.Add(1)

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whetever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA1", func(t *testing.T) {
		testRSASignDigestPSS(t, key1024, crypto.SHA1, rsa.PSSSaltLengthEqualsHash)
		awaitElement.Done()
	}) // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	awaitElement.Wait()
	awaitElement.Add(1)
	t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA256", func(t *testing.T) {
		testRSASignDigestPSS(t, key1024, crypto.SHA256, rsa.PSSSaltLengthEqualsHash)
		awaitElement.Done()
	}) // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	//t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA384, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA512, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	awaitElement.Wait()
	awaitElement.Add(1)
	t.Run("RSASIGNPSS-1024-SALTAUTO-SHA1", func(t *testing.T) {
		testRSASignDigestPSS(t, key1024, crypto.SHA1, rsa.PSSSaltLengthAuto)
		awaitElement.Done()
	})
	awaitElement.Wait()
	awaitElement.Add(1)
	t.Run("RSASIGNPSS-1024-SALTAUTO-SHA256", func(t *testing.T) {
		testRSASignDigestPSS(t, key1024, crypto.SHA256, rsa.PSSSaltLengthAuto)
		awaitElement.Done()
	})
	//t.Run("RSASIGNPSS-1024-SALTAUTO-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA384, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-1024-SALTAUTO-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA512, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	awaitElement.Wait()
	awaitElement.Add(1)
	t.Run("RSASIGNPKCS-1024-SHA1", func(t *testing.T) {
		testRSASignDigestPKCS1v15(t, key1024, crypto.SHA1)
		awaitElement.Done()
	})
	awaitElement.Wait()
	awaitElement.Add(1)
	t.Run("RSASIGNPKCS-1024-SHA256", func(t *testing.T) {
		testRSASignDigestPKCS1v15(t, key1024, crypto.SHA256)
		awaitElement.Done()
	})
	awaitElement.Wait()
	awaitElement.Add(1)
	t.Run("RSASIGNPKCS-1024-SHA384", func(t *testing.T) {
		testRSASignDigestPKCS1v15(t, key1024, crypto.SHA384)
		awaitElement.Done()
	})
	awaitElement.Wait()
	awaitElement.Add(1)
	t.Run("RSASIGNPKCS-1024-SHA512", func(t *testing.T) {
		testRSASignDigestPKCS1v15(t, key1024, crypto.SHA512)
		awaitElement.Done()
	})
}
*/

func TestRSASignWithoutPass(t *testing.T) {

	// Generate key
	key1024, err := GenerateRSAKey("", "", false, false, 1024, 0, true)
	require.NoError(t, err)
	require.NotNil(t, key1024)
	defer func() {
		require.NoError(t, key1024.Delete())
	}()

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whetever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA1, rsa.PSSSaltLengthEqualsHash) })     // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA256, rsa.PSSSaltLengthEqualsHash) }) // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	//t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA384, rsa.PSSSaltLengthEqualsHash) }) // TE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-1024-SALTEQUALS-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA512, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPSS-1024-SALTAUTO-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA1, rsa.PSSSaltLengthAuto) })
	t.Run("RSASIGNPSS-1024-SALTAUTO-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA256, rsa.PSSSaltLengthAuto) })
	//t.Run("RSASIGNPSS-1024-SALTAUTO-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA384, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-1024-SALTAUTO-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key1024, crypto.SHA512, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPKCS-1024-SHA1", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA1) })
	t.Run("RSASIGNPKCS-1024-SHA256", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA256) })
	t.Run("RSASIGNPKCS-1024-SHA384", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA384) })
	t.Run("RSASIGNPKCS-1024-SHA512", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key1024, crypto.SHA512) })

	// Generate key
	key2048, err := GenerateRSAKey("", "", false, false, 2048, 0, true)
	require.NoError(t, err)
	require.NotNil(t, key2048)
	defer func() {
		require.NoError(t, key2048.Delete())
	}()

	// At the time of writing, we have the following :
	// 1 / Setting salt length in padding info always fails, whetever its value is.
	// 2 / As a result, setting NCRYPT_TPM_PAD_PSS_IGNORE_SALT when signing is needed, which means
	//	   the PCP KSP disregards any salt length passed in the padding info and always makes use of
	//     the TPM's chip default salt length.
	// 3/ Signing SHA-384/512 digests with RSA-PSS always fails with NTE_NOT_SUPPORTED.
	t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA1, rsa.PSSSaltLengthEqualsHash) })     // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA256, rsa.PSSSaltLengthEqualsHash) }) // TPM_E_PCP_UNSUPPORTED_PSS_SALT on pre 1.16 ?
	//t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA384, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-2048-SALTEQUALS-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA512, rsa.PSSSaltLengthEqualsHash) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPSS-2048-SALTAUTO-SHA1", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA1, rsa.PSSSaltLengthAuto) })
	t.Run("RSASIGNPSS-2048-SALTAUTO-SHA256", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA256, rsa.PSSSaltLengthAuto) })
	//t.Run("RSASIGNPSS-2048-SALTAUTO-SHA384", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA384, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	//t.Run("RSASIGNPSS-2048-SALTAUTO-SHA512", func(t *testing.T) { testRSASignDigestPSS(t, key2048, crypto.SHA512, rsa.PSSSaltLengthAuto) }) // NTE_NOT_SUPPORTED
	t.Run("RSASIGNPKCS-2048-SHA1", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA1) })
	t.Run("RSASIGNPKCS-2048-SHA256", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA256) })
	t.Run("RSASIGNPKCS-2048-SHA384", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA384) })
	t.Run("RSASIGNPKCS-2048-SHA512", func(t *testing.T) { testRSASignDigestPKCS1v15(t, key2048, crypto.SHA512) })
}
