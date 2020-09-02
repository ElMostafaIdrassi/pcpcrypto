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
	"testing"

	"crypto/elliptic"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func testFindKey(t *testing.T, name string, password string, length int) {
	key, err := FindKey(name, password)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, key.Name(), name)
	require.Equal(t, key.Size(), (length+7)/8)
}

func testFindAndDeleteKey(t *testing.T, name string) {
	key, err := FindKey(name, "")
	require.NoError(t, err)
	require.NotNil(t, key)
	require.NoError(t, key.Delete())
}

func TestRSADeleteKey(t *testing.T) {

	// Generate a new RSA-1024 key with a random unique name and an empty password
	uuidName, err := uuid.NewRandom()
	require.NoError(t, err)
	length := 1024
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
	require.Equal(t, key.Size(), (curve.Params().BitSize+7)/8)

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
