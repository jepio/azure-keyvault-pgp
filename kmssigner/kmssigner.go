// Copyright © 2018 Heptio
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

// Package kmssigner implements a crypto.Signer backed by Google Cloud KMS.
package kmssigner

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/pkg/errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	azcrypto "github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys/crypto"
)

// Signer extends crypto.Signer to provide more key metadata.
type Signer interface {
	crypto.Signer
	RSAPublicKey() *rsa.PublicKey
	CreationTime() time.Time
}

// New returns a crypto.Signer backed by the named Google Cloud KMS key.
func New(api *azkeys.Client, cred *azidentity.DefaultAzureCredential, name string) (Signer, error) {
	ctx := context.Background()
	resp, err := api.GetKey(ctx, name, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "could not get key version from Azure Keyvault")
	}
	switch *resp.JSONWebKey.KeyType {
	case azkeys.KeyTypeRSA:
	case azkeys.KeyTypeRSAHSM:
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", *resp.Key.JSONWebKey.KeyType)
	}

	creationTime := *resp.Properties.CreatedOn

	jwk := resp.JSONWebKey
	if len(jwk.E) != 3 {
		return nil, fmt.Errorf("unsupported exponent: %q", jwk.E)
	}
	E := (int(jwk.E[0]) << 16) | (int(jwk.E[1]) << 8) | (int(jwk.E[0]) << 0)
	N := new(big.Int)
	N.SetBytes(jwk.N)
	pubkeyRSA := rsa.PublicKey{
		E: E,
		N: N,
	}
	capi, err := azcrypto.NewClient(*resp.JSONWebKey.ID, cred, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create Crypto client")
	}
	return &kmsSigner{
		api:          capi,
		name:         name,
		pubkey:       pubkeyRSA,
		creationTime: creationTime,
	}, nil
}

type kmsSigner struct {
	api          *azcrypto.Client
	name         string
	pubkey       rsa.PublicKey
	creationTime time.Time
}

func (k *kmsSigner) Public() crypto.PublicKey {
	return k.pubkey
}

func (k *kmsSigner) RSAPublicKey() *rsa.PublicKey {
	return &k.pubkey
}

func (k *kmsSigner) CreationTime() time.Time {
	return k.creationTime
}

func (k *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("input digest must be valid SHA-256 hash")
	}
	ctx := context.Background()
	sig, err := k.api.Sign(ctx, azcrypto.SignatureAlgorithmRS256, digest, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error signing with Azure Keyvault")
	}
	return sig.Result, nil
}
