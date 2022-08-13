package main

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wireguardPeer struct {
	AllowedIPs []string `json:"allowed_ips" mapstructure:"allowed_ips"`
	Hostname   string   `json:"hostname" mapstructure:"hostname"`
	Name       string   `json:"name" mapstructure:"name"`
	Port       int      `json:"port" mapstructure:"port"`
	PrivateKey string   `json:"private_key" mapstructure:"private_key"`
	PublicKey  string   `json:"public_key" mapstructure:"public_key"`
}

func getPeer(ctx context.Context, s logical.Storage, groupname, name string) (*wireguardPeer, error) {
	if groupname == "" {
		return nil, fmt.Errorf("missing group name")
	}

	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	entry, err := s.Get(ctx, "groups/"+groupname+"/"+name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving peer: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	var peer wireguardPeer

	if err := entry.DecodeJSON(&peer); err != nil {
		return nil, fmt.Errorf("error decoding peer data: %w", err)
	}

	return &peer, nil
}

func (b *wireguardBackend) pathPeersList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "groups/"+data.Get("name").(string)+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *wireguardBackend) pathPeersDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupname := data.Get("group_name").(string)

	b.lock.Lock()

	if err := req.Storage.Delete(ctx, "groups/"+groupname+"/"+data.Get("name").(string)); err != nil {
		b.lock.Unlock()
		return nil, err
	}

	b.lock.Unlock()

	return b.updateGroupPeers(ctx, req.Storage, groupname)
}

func (b *wireguardBackend) pathPeersRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	peer, err := getPeer(ctx, req.Storage, data.Get("group_name").(string), data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if peer == nil {
		return nil, nil
	}

	var groupMap map[string]interface{}

	err = mapstructure.Decode(peer, &groupMap)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: groupMap,
	}, nil
}

func (b *wireguardBackend) pathPeersWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupname := data.Get("group_name").(string)
	if groupname == "" {
		return logical.ErrorResponse("missing group name"), nil
	}

	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	group, err := getGroup(ctx, req.Storage, groupname)
	if err != nil || group == nil {
		return logical.ErrorResponse("missing group"), err
	}

	peer, err := getPeer(ctx, req.Storage, groupname, name)
	if err != nil {
		return logical.ErrorResponse("missing peer"), err
	}

	if peer == nil {
		peer = &wireguardPeer{}
	}

	peer.Name = name

	if allowedIPs, ok := data.GetOk("allowed_ips"); ok {
		prefixes := []string{}

		for _, ip := range allowedIPs.([]string) {
			prefix, err := netip.ParsePrefix(ip)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("error parsing allowed_ips %s: %e", ip, err)), err
			}

			prefixes = append(prefixes, prefix.String())
		}

		peer.AllowedIPs = prefixes
	}

	if hostname, ok := data.GetOk("hostname"); ok && hostname != "" {
		peer.Hostname = hostname.(string)
	} else {
		peer.Hostname = name
	}

	if port, ok := data.GetOk("port"); ok {
		peer.Port = port.(int)
	}

	if privateKey, ok := data.GetOk("private_key"); ok {
		key, err := wgtypes.ParseKey(privateKey.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("error parsing private_key: %e", err)), err
		}

		peer.PrivateKey = privateKey.(string)
		peer.PublicKey = key.PublicKey().String()
	}

	if publicKey, ok := data.GetOk("public_key"); ok {
		peer.PublicKey = publicKey.(string)
	}

	if peer.PrivateKey == "" && peer.PublicKey == "" {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("error generating private_key: %e", err)), err
		}

		peer.PrivateKey = key.String()
		peer.PublicKey = key.PublicKey().String()
	}

	if err := b.put(ctx, req.Storage, "groups/"+groupname+"/"+name, peer); err != nil {
		return nil, err
	}

	return b.updateGroupPeers(ctx, req.Storage, groupname)
}

func (b *wireguardBackend) pathPeersWGQuickRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupname := data.Get("group_name").(string)
	if groupname == "" {
		return logical.ErrorResponse("missing group name"), nil
	}

	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	group, err := getGroup(ctx, req.Storage, groupname)
	if err != nil || group == nil {
		return logical.ErrorResponse("unable to find group"), nil
	}

	var config bytes.Buffer

	if err := wgQuickTemplate.Execute(&config, wgQuickValues{
		Group: group,
		Name:  name,
	}); err != nil {
		return logical.ErrorResponse("error rendering config: %w", err), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"config":  config.String(),
			"max_ttl": group.MaxTTL,
			"ttl":     group.TTL,
		},
	}, nil
}
