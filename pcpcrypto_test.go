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
	"testing"

	"crypto/elliptic"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGetKeys(t *testing.T) {
	uuidName1, err := uuid.NewRandom()
	require.NoError(t, err)
	length := uint32(1024)
	name1 := uuidName1.String()
	key1, err := GenerateRSAKey(name1, "", length, true)
	defer key1.Delete()
	require.NoError(t, err)
	require.NotNil(t, key1)
	require.Equal(t, key1.Name(), name1)
	require.Equal(t, key1.Size(), (length+7)/8)

	uuidName2, err := uuid.NewRandom()
	require.NoError(t, err)
	name2 := uuidName2.String()
	key2, err := GenerateECDSAKey(name2, "", elliptic.P256(), true)
	defer key2.Delete()
	require.NoError(t, err)
	require.NotNil(t, key2)
	require.Equal(t, key2.Name(), name2)
	require.Equal(t, key2.Size(), uint32((elliptic.P256().Params().BitSize+7)/8))

	foundKey1 := false
	foundKey2 := false
	keys, err := GetKeys()
	require.NoError(t, err)
	for _, key := range keys {
		if key.Name() == key1.Name() && key.Size() == key1.Size() {
			foundKey1 = true
		}
		if key.Name() == key2.Name() && key.Size() == key2.Size() {
			foundKey2 = true
		}
	}
	require.Equal(t, foundKey1, true)
	require.Equal(t, foundKey2, true)
}

func TestRSADeleteKey(t *testing.T) {

	// Generate a new RSA-1024 key with a random unique name and an empty password
	uuidName, err := uuid.NewRandom()
	require.NoError(t, err)
	length := uint32(1024)
	name := uuidName.String()
	key, err := GenerateRSAKey(name, "", length, true)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, key.Name(), name)
	require.Equal(t, key.Size(), (length+7)/8)

	// Find the RSA-1024 key
	keyBis, err := FindKey(name, "")
	require.NoError(t, err)
	require.NotNil(t, keyBis)
	require.Equal(t, key.Name(), keyBis.Name())
	require.Equal(t, key.Size(), keyBis.Size())
	require.Equal(t, key.Public(), keyBis.Public())

	// Delete the RSA-1024 key
	require.NoError(t, key.Delete())

	// Now, it should not be possible to find the RSA-1024 key
	keyBis, err = FindKey(name, "")
	require.Error(t, err)
	require.Nil(t, keyBis)
}

func TestECDSADeleteKey(t *testing.T) {

	// Generate a new ECDSA-P256 key with a random name and an empty password
	uuidName, err := uuid.NewRandom()
	require.NoError(t, err)
	curve := elliptic.P256()
	name := uuidName.String()
	key, err := GenerateECDSAKey(name, "", curve, true)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, key.Name(), name)
	require.Equal(t, key.Size(), uint32(((curve.Params().BitSize + 7) / 8)))

	// Find the ECDSA-P256 key
	keyBis, err := FindKey(name, "")
	require.NoError(t, err)
	require.NotNil(t, keyBis)
	require.Equal(t, key.Name(), keyBis.Name())
	require.Equal(t, key.Size(), keyBis.Size())
	require.Equal(t, key.Public(), keyBis.Public())

	// Delete the ECDSA-P256 key
	require.NoError(t, key.Delete())

	// Now, it should not be possible to find the ECDSA-P256 key
	keyBis, err = FindKey(name, "")
	require.Error(t, err)
	require.Nil(t, keyBis)
}
