package signer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/go-jose/go-jose/v4"
	"github.com/nais/digdirator/internal/crypto"
)

var _ ByteSigner = (*AkvByteSigner)(nil)

type akvKeyClient interface {
	Sign(ctx context.Context, name, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

type AkvByteSigner struct {
	Client     akvKeyClient
	KeyName    string
	KeyVersion string
}

// NewAkvSigner signs with an Azure Key Vault RSA key, e.g. https://<vault>.vault.azure.net/keys/<name>[/<version>].
// The JWT header contains keyID as "kid" if set (key registered on the DigDir admin client), otherwise pemChain as "x5c".
func NewAkvSigner(ctx context.Context, keyPath, keyID string, pemChain []byte) (jose.Signer, error) {
	vaultURL, keyName, keyVersion, err := parseAkvKeyPath(keyPath)
	if err != nil {
		return nil, err
	}

	opts, err := akvSignerOptions(keyID, pemChain)
	if err != nil {
		return nil, err
	}

	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("creating azure credential: %w", err)
	}

	client, err := azkeys.NewClient(vaultURL, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("creating key vault key client: %w", err)
	}

	resp, err := client.GetKey(ctx, keyName, keyVersion, nil)
	if err != nil {
		return nil, fmt.Errorf("getting key %q: %w", keyPath, err)
	}

	key := resp.Key
	if key == nil || key.KID == nil || len(key.N) == 0 || len(key.E) == 0 {
		return nil, fmt.Errorf("key %q is not an RSA key", keyPath)
	}

	return newAkvSigner(client, key.KID.Name(), key.KID.Version(), opts), nil
}

func akvSignerOptions(keyID string, pemChain []byte) (*jose.SignerOptions, error) {
	opts := &jose.SignerOptions{}
	opts.WithType("JWT")

	if keyID != "" {
		opts.WithHeader("kid", keyID)
		return opts, nil
	}

	certs, err := crypto.ConvertPEMChainToX509Chain(pemChain)
	if err != nil {
		return nil, fmt.Errorf("converting PEM cert chain to X509 cert chain: %w", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("either key ID or certificate chain must be set")
	}

	opts.WithHeader("x5c", crypto.ConvertX509CertificatesToX5c(certs))
	return opts, nil
}

func parseAkvKeyPath(keyPath string) (vaultURL, name, version string, err error) {
	u, err := url.Parse(keyPath)
	if err != nil {
		return "", "", "", fmt.Errorf("parsing key path: %w", err)
	}

	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if u.Scheme != "https" || u.Host == "" || len(segments) < 2 || len(segments) > 3 || segments[0] != "keys" || segments[1] == "" {
		return "", "", "", fmt.Errorf("invalid key path %q, expected https://<vault>.vault.azure.net/keys/<name>[/<version>]", keyPath)
	}

	if len(segments) == 3 {
		version = segments[2]
	}

	return fmt.Sprintf("https://%s", u.Host), segments[1], version, nil
}

func newAkvSigner(client akvKeyClient, keyName, keyVersion string, opts *jose.SignerOptions) jose.Signer {
	return ConfigurableSigner{
		SignerOptions: opts,
		ByteSigner: AkvByteSigner{
			Client:     client,
			KeyName:    keyName,
			KeyVersion: keyVersion,
		},
	}
}

func (a AkvByteSigner) SignBytes(payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	algorithm := azkeys.SignatureAlgorithmRS256

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	response, err := a.Client.Sign(ctx, a.KeyName, a.KeyVersion, azkeys.SignParameters{
		Algorithm: &algorithm,
		Value:     digest[:],
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	return response.Result, nil
}
