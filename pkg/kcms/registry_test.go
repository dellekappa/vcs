/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kcms_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/kcms"
)

func TestNewRegistry(t *testing.T) {
	r := kcms.NewRegistry(nil, kcms.Config{}, nil)
	require.NotNil(t, r)
}

func TestRegistry_GetKeyManager(t *testing.T) {
	t.Run("Default config local kms", func(t *testing.T) {
		r := kcms.NewRegistry(nil, kcms.Config{KMSType: kcms.Local}, nil)
		require.NotNil(t, r)

		_, err := r.GetKeyManager(nil)
		require.NoError(t, err)
	})

	t.Run("Fallback kms", func(t *testing.T) {
		r := kcms.NewRegistry(nil, kcms.Config{KMSType: kcms.Local}, nil)
		require.NotNil(t, r)

		_, err := r.GetKeyManager(&kcms.Config{
			KMSType: "aws",
		})

		require.NoError(t, err)
	})
}
