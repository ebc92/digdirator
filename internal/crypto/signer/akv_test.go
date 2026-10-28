package signer

import (
	"context"
	libcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeKeyClient struct {
	key          *rsa.PrivateKey
	gotName      string
	gotVersion   string
	gotAlgorithm azkeys.SignatureAlgorithm
}

func (f *fakeKeyClient) Sign(_ context.Context, name, version string, parameters azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	f.gotName = name
	f.gotVersion = version
	f.gotAlgorithm = *parameters.Algorithm

	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, libcrypto.SHA256, parameters.Value)
	if err != nil {
		return azkeys.SignResponse{}, err
	}

	return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: signature}}, nil
}

func TestAkvSigner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	client := &fakeKeyClient{key: key}
	opts, err := akvSignerOptions("some-kid", nil)
	require.NoError(t, err)
	s := newAkvSigner(client, "some-key", "some-version", opts)

	claims := jwt.Claims{
		Issuer:   "some-admin-client",
		Audience: []string{"https://test.maskinporten.no/"},
		Expiry:   jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
	}

	token, err := jwt.Signed(s).Claims(claims).Serialize()
	require.NoError(t, err)

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{SigningAlg})
	require.NoError(t, err)
	require.Len(t, parsed.Headers, 1)

	rawHeader, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	require.NoError(t, err)

	var header map[string]any
	require.NoError(t, json.Unmarshal(rawHeader, &header))
	assert.Equal(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "some-kid"}, header)

	var got jwt.Claims
	require.NoError(t, parsed.Claims(&key.PublicKey, &got))
	assert.Equal(t, claims.Issuer, got.Issuer)

	assert.Equal(t, "some-key", client.gotName)
	assert.Equal(t, "some-version", client.gotVersion)
	assert.Equal(t, azkeys.SignatureAlgorithmRS256, client.gotAlgorithm)
}

func TestAkvSignerOptions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "some-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	pemChain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	t.Run("kid takes precedence over x5c", func(t *testing.T) {
		opts, err := akvSignerOptions("some-kid", pemChain)
		require.NoError(t, err)
		assert.Equal(t, "some-kid", opts.ExtraHeaders["kid"])
		assert.NotContains(t, opts.ExtraHeaders, jose.HeaderKey("x5c"))
	})

	t.Run("x5c without kid", func(t *testing.T) {
		opts, err := akvSignerOptions("", pemChain)
		require.NoError(t, err)
		assert.Equal(t, []string{base64.StdEncoding.EncodeToString(der)}, opts.ExtraHeaders["x5c"])
		assert.NotContains(t, opts.ExtraHeaders, jose.HeaderKey("kid"))
	})

	t.Run("neither kid nor x5c", func(t *testing.T) {
		_, err := akvSignerOptions("", nil)
		assert.Error(t, err)
	})
}

func TestParseAkvKeyPath(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantVault   string
		wantName    string
		wantVersion string
		wantErr     bool
	}{
		{name: "without version", input: "https://some-kv.vault.azure.net/keys/some-key", wantVault: "https://some-kv.vault.azure.net", wantName: "some-key"},
		{name: "with version", input: "https://some-kv.vault.azure.net/keys/some-key/abc123", wantVault: "https://some-kv.vault.azure.net", wantName: "some-key", wantVersion: "abc123"},
		{name: "trailing slash", input: "https://some-kv.vault.azure.net/keys/some-key/", wantVault: "https://some-kv.vault.azure.net", wantName: "some-key"},
		{name: "certificates path", input: "https://some-kv.vault.azure.net/certificates/some-key", wantErr: true},
		{name: "vault only", input: "https://some-kv.vault.azure.net", wantErr: true},
		{name: "http", input: "http://some-kv.vault.azure.net/keys/some-key", wantErr: true},
		{name: "too many segments", input: "https://some-kv.vault.azure.net/keys/some-key/v1/extra", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vault, name, version, err := parseAkvKeyPath(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantVault, vault)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}
