package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

type wireguardGroup struct {
	Name                string               `json:"name" mapstructure:"name"`
	Network             netip.Prefix         `json:"network" mapstructure:"network"`
	Peers               []wireguardGroupPeer `json:"peers" mapstructure:"peers"`
	PersistentKeepalive int                  `json:"persistent_keepalive" mapstructure:"persistent_keepalive"`
	TTL                 int                  `json:"ttl" mapstructure:"ttl"`
	MaxTTL              int                  `json:"max_ttl" mapstructure:"max_ttl"`
}

type wireguardGroupPeer struct {
	AllowedIPs          string `json:"allowed_ips"`
	Hostname            string `json:"hostname"`
	IP                  string `json:"ip"`
	Name                string `json:"name"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
	Port                int    `json:"port"`
	PrivateKey          string `json:"private_key"`
	PublicKey           string `json:"public_key"`
}

func getGroup(ctx context.Context, s logical.Storage, name string) (*wireguardGroup, error) {
	if name == "" {
		return nil, fmt.Errorf("missing group name")
	}

	entry, err := s.Get(ctx, "groups/"+name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving group: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	var group wireguardGroup

	if err := entry.DecodeJSON(&group); err != nil {
		return nil, fmt.Errorf("error decoding group data: %w", err)
	}

	return &group, nil
}

func (b *wireguardBackend) updateGroupPeers(ctx context.Context, s logical.Storage, name string) (*logical.Response, error) {
	group, err := getGroup(ctx, s, name)
	if err != nil {
		return nil, err
	}

	peerNames, err := s.List(ctx, "groups/"+name+"/")
	if err != nil {
		return logical.ErrorResponse("no peers in group"), err
	}

	ip := group.Network.Addr()
	group.Peers = make([]wireguardGroupPeer, len(peerNames))

	for i := range peerNames {
		ip = ip.Next()
		addr := fmt.Sprintf("%s/%d", ip, group.Network.Bits())
		allow := ip.String()

		if ip.Is4() {
			allow += "/32"
		} else {
			allow += "/128"
		}

		p, err := getPeer(ctx, s, name, peerNames[i])
		if err != nil {
			return nil, err
		}

		peer := wireguardGroupPeer{
			AllowedIPs: strings.Join(append([]string{allow}, p.AllowedIPs...), ","),
			IP:         addr,
			Hostname:   p.Hostname,
			Name:       p.Name,
			Port:       p.Port,
			PrivateKey: p.PrivateKey,
			PublicKey:  p.PublicKey,
		}

		if peer.Port == 0 {
			peer.PersistentKeepalive = group.PersistentKeepalive
		}

		group.Peers[i] = peer
	}

	err = b.put(ctx, s, "groups/"+name, group)

	return nil, err
}

func (b *wireguardBackend) pathGroupsList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "groups/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *wireguardBackend) pathGroupsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupname := data.Get("name").(string)

	b.lock.Lock()
	defer b.lock.Unlock()

	if err := req.Storage.Delete(ctx, "groups/"+groupname); err != nil {
		return nil, err
	}

	peerNames, err := req.Storage.List(ctx, "groups/"+groupname+"/")
	if err != nil {
		return logical.ErrorResponse("no peers in group"), err
	}

	for i := range peerNames {
		if err := req.Storage.Delete(ctx, "groups/"+groupname+"/"+peerNames[i]); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

func (b *wireguardBackend) pathGroupsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	group, err := getGroup(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if group == nil {
		return nil, nil
	}

	var groupMap map[string]interface{}

	err = mapstructure.Decode(group, &groupMap)
	if err != nil {
		return nil, err
	}

	delete(groupMap, "peers")
	groupMap["network"] = group.Network.String()

	return &logical.Response{
		Data: groupMap,
	}, nil
}

func (b *wireguardBackend) pathGroupsWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing group name"), nil
	}

	group, err := getGroup(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if group == nil {
		group = &wireguardGroup{}
	}

	group.Name = name
	create := (req.Operation == logical.CreateOperation)

	if network, ok := data.GetOk("network"); ok {
		prefix, err := netip.ParsePrefix(network.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("error parsing network: %e", err)), nil
		}

		group.Network = prefix
	} else if create {
		return logical.ErrorResponse("missing network field"), nil
	}

	if ttl, ok := data.GetOk("ttl"); ok && ttl.(int) != 0 {
		group.TTL = int((time.Duration(ttl.(int)) * time.Second).Seconds())
	} else {
		group.TTL = int(time.Duration(60 * time.Second).Seconds())
	}

	if maxTTL, ok := data.GetOk("ttl"); ok && maxTTL.(int) != 0 {
		group.MaxTTL = int((time.Duration(maxTTL.(int)) * time.Second).Seconds())
	} else {
		group.MaxTTL = int(time.Duration(60 * time.Second).Seconds())
	}

	if persistentKeepalive, ok := data.GetOk("persistent_keepalive"); ok {
		group.PersistentKeepalive = persistentKeepalive.(int)
	}

	if err := b.put(ctx, req.Storage, "groups/"+name, group); err != nil {
		return nil, err
	}

	return b.updateGroupPeers(ctx, req.Storage, group.Name)
}
