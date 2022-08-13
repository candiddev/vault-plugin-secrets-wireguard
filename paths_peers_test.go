package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const publicKey = "lpTCQOdhnt1nTRdcuhuVLNNhk6Azr2WDZ1xJKofUfnE="
const privateKey = "sK5mAmlrbsEvhQBpn5quJi/7xrhooUkkaw8rtaM8F0k="

func TestPeers(t *testing.T) {
	b, s := getTestBackend(t)
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup",
		Storage:   s,
		Data: map[string]interface{}{
			"network":              "10.0.0.0/24",
			"persistent_keepalive": 30,
		},
	}
	b.HandleRequest(context.Background(), req)

	// Create
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup1/peer1",
		Storage:   s,
		Data: map[string]interface{}{
			"allowed_ips": "10.20.0.0/24,10.30.0.0/24",
			"port":        51822,
			"private_key": privateKey,
		},
	}

	res, err := b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Equal(t, "missing group", res.Error().Error())

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup/peer1",
		Storage:   s,
		Data: map[string]interface{}{
			"allowed_ips": "10.20.0.0/24,10.30.0.0/24",
			"port":        51822,
			"private_key": privateKey,
		},
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup/peer2",
		Storage:   s,
		Data: map[string]interface{}{
			"allowed_ips":          "10.20.0.0/24,10.30.0.0/24",
			"persistent_keepalive": 30,
			"private_key":          privateKey,
			"public_key":           publicKey,
		},
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup/peer3",
		Storage:   s,
		Data: map[string]interface{}{
			"port": "51820",
		},
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup/peer4",
		Storage:   s,
		Data:      map[string]interface{}{},
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	// Update
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "groups/mygroup/peer1",
		Storage:   s,
		Data: map[string]interface{}{
			"port": 51823,
		},
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	// Read
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "groups/mygroup/peer3",
		Storage:   s,
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	var str []string
	peer3 := map[string]interface{}{
		"allowed_ips": str,
		"hostname":    "peer3",
		"name":        "peer3",
		"port":        51820,
		"public_key":  res.Data["public_key"],
		"private_key": res.Data["private_key"],
	}
	require.Equal(t, peer3, res.Data)

	// Delete
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "groups/mygroup/peer4",
		Storage:   s,
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Nil(t, res)

	// List
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "groups/mygroup/",
		Storage:   s,
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Equal(t, []string{"peer1", "peer2", "peer3"}, res.Data["keys"])

	// Get config
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "groups/mygroup/peer1/wg-quick",
		Storage:   s,
	}

	res, err = b.HandleRequest(context.Background(), req)
	require.Nil(t, err)
	require.Equal(t, fmt.Sprintf(`# mygroup/peer1

[Interface]
Address=10.0.0.1/24
PrivateKey=%s
ListenPort=51823

# peer2
[Peer]
PublicKey=%s
AllowedIPs=10.0.0.2/32,10.20.0.0/24,10.30.0.0/24
PersistentKeepalive=30

# peer3
[Peer]
PublicKey=%s
AllowedIPs=10.0.0.3/32
Endpoint=peer3:51820
`, privateKey, publicKey, peer3["public_key"]), res.Data["config"])
}
