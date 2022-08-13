package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type wireguardBackend struct {
	*framework.Backend
	lock sync.Mutex
}

func (b *wireguardBackend) put(ctx context.Context, s logical.Storage, path string, data interface{}) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	entry, err := logical.StorageEntryJSON(path, data)
	if err != nil {
		return fmt.Errorf("error creating storage entry: %w", err)
	}

	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("error writing to backend: %w", err)
	}

	return nil
}

func newBackend(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := wireguardBackend{}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help: strings.TrimSpace(`
The Wireguard secrets backend manages Wireguard keys and configs.
`),
		Paths: paths(&b),
		PathsSpecial: &logical.Paths{
			LocalStorage:    []string{},
			SealWrapStorage: []string{},
		},
		Secrets: []*framework.Secret{},
	}

	return &b, nil
}
