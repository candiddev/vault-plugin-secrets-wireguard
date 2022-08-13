package main

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func paths(b *wireguardBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "groups" + "/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathGroupsList,
				},
			},
			HelpDescription: "List the group names",
			HelpSynopsis:    "List groups",
		},
		{
			Pattern: "groups/" + framework.GenericNameRegex("name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the group",
					Required:    true,
				},
				"network": {
					Type:        framework.TypeLowerCaseString,
					Description: "The network the group will have IP addresses on.  Must be in the form of a valid IPv4 (1.1.1.1/24) or IPv6 (a:b:c::/64) prefix.  Ensure the network is big enough for the number of peers in the group + 2.",
					Required:    true,
				},
				"persistent_keepalive": {
					Type:        framework.TypeInt,
					Description: "Override the default engine PersistentKeepalive value for this group.",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated configs. If not set or set to 0, will be 1m.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will be 1.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathGroupsRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathGroupsWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathGroupsWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathGroupsDelete,
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathPeersList,
				},
			},
			HelpSynopsis:    "Manage Wireguard groups which contain Wireguard peers",
			HelpDescription: "Manage groups",
		},
		{
			Pattern: "groups/" + framework.GenericNameRegex("name") + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Group name to lookup peers for.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathPeersList,
				},
			},
			HelpDescription: "List the group peer names",
			HelpSynopsis:    "List group peers",
		},
		{
			Pattern: "groups/" + framework.GenericNameRegex("group_name") + "/" + framework.GenericNameRegex("name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Group name to associate the peer with.",
					Required:    true,
				},
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the peer.",
					Required:    true,
				},
				"allowed_ips": {
					Type:        framework.TypeCommaStringSlice,
					Description: "List of additional AllowedIPs for the peer.  Must be valid IP prefixes.  Will include the Peer's assigned IP by default.",
				},
				"hostname": {
					Type:        framework.TypeLowerCaseString,
					Description: "Hostname of the peer.  If a port is provided, will be combined with port as an endpoint, otherwise will just be used as a client.  If not specified, will use name.",
				},
				"port": {
					Type:        framework.TypeInt,
					Description: "Wireguard listening port, if not provided the peer will not be registered as an endpoint.",
				},
				"private_key": {
					Type:        framework.TypeString,
					Description: "Wireguard private key, if not provided one will be generated",
				},
				"public_key": {
					Type:        framework.TypeString,
					Description: "Wireguard public key, if not provided one will be generated",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathPeersRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathPeersWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathPeersWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathPeersDelete,
				},
			},
			HelpSynopsis:    "Manage Wireguard peer configurations",
			HelpDescription: "Manage peers",
		},
		{
			Pattern: "groups/" + framework.GenericNameRegex("group_name") + "/" + framework.GenericNameRegex("name") + "/wg-quick$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Group name for peer.",
					Required:    true,
				},
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name for peer.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathPeersWGQuickRead,
				},
			},
			HelpSynopsis:    "Read a config suitable for wg-quick",
			HelpDescription: "Read wg-quick config",
		},
	}
}
