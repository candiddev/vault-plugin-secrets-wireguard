package main

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestGroups(t *testing.T) {
	b, s := getTestBackend(t)

	// Create
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup1",
		Storage:   s,
		Data: map[string]interface{}{
			"network":              "10.0.0.0/24",
			"persistent_keepalive": 30,
		},
	}

	res, err := b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup2",
		Storage:   s,
		Data: map[string]interface{}{
			"network":              "10.0.0.0/24",
			"persistent_keepalive": 30,
		},
	}
	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	// Update
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup1",
		Storage:   s,
		Data: map[string]interface{}{
			"network":              "10.1.0.0/24",
			"persistent_keepalive": 45,
		},
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	// Read
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "groups/mygroup1",
		Storage:   s,
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Equal(t, map[string]interface{}{
		"max_ttl":              60,
		"name":                 "mygroup1",
		"network":              "10.1.0.0/24",
		"persistent_keepalive": 45,
		"ttl":                  60,
	}, res.Data)

	// Delete
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "groups/mygroup1",
		Storage:   s,
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "groups/mygroup1",
		Storage:   s,
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	// List
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "groups",
		Storage:   s,
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Equal(t, res.Data["keys"], []string{"mygroup2"})

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "groups/mygroup2",
		Storage:   s,
	}

	b.HandleRequest(context.Background(), req)
}
