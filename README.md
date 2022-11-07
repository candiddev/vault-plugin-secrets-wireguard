# Vault Plugin: Wireguard Secrets Engine

> Automatically generate Wireguard keys and configurations for your servers to create a Wireguard mesh network.

## Archived

Vault doesn't have a good way to watch changes, so this plugin leveraged a low TTL to have clients constantly check for new members.  At scale, this causes some weird race conditions as clients eventually connect.  The TTL can be tweaked up/down in theory, but that puts more load on the Vault server.

Instead, we switched to using Consul watches and store the WireGuard public key in the Consul node meta.  Consul watches iterate through all nodes on changes and render a new WireGuard private key definition.

## Install

1. Add `plugin_directory = "<folder-where-you-will-put-the plugin>"` to your vault config
2. Download the plugin from [releases](https://github.com/candiddev/vault-plugin-secrets-wireguard/releases) page to the folder above and decompress it.  Keep the name with the version in it.
3. Register the plugin in vault:
```
$ vault plugin register -command=${PLUGIN_PATH} -sha256=$(sha256sum ${PLUGIN_PATH} | cut -d\  -f 1)) vault-plugin-secrets-wireguard
```
4. Enable the plugin in vault:
```
$ vault secrets enable -description='wireguard keys' -path=wireguard vault-plugin-secrets-wireguard
```

## Upgrade

1. Download a newer version of the plugin from [releases](https://github.com/candiddev/vault-plugin-secrets-wireguard/releases) page to the folder above and decompress it.  Keep the name with the version in it.
2. Register the new version:
```
$ vault plugin register -command=${PLUGIN_PATH} -sha256=$(sha256sum ${PLUGIN_PATH} | cut -d\  -f 1)) vault-plugin-secrets-wireguard
```
3. Reload the plugin:
```
$ vault plugin reload -plugin=vault-plugin-secrets-wireguard
```

## Usage

After installing the secrets engine, you can configure groups and associate peers with the group.

### Groups

* Add a group with the name 'mygroup' using the network '10.0.0.0/24':
```
$ vault write wireguard/groups/mygroup network=10.0.0.0/24
```

* Change the group to use the network '10.1.0.0/24'
```
$ vault write wireguard/groups/mygroup network=10.1.0.0/24
```

* Delete the group
```
$ vault delete wireguard/groups/mygroup
```

### Peers

* Add a peer with a hostname of peer1 and a static port of 51820 (the public and private key will be generated automatically):

```
$ vault write wireguard/groups/mygroup/peer1 port=51820
```

* Change the peer's wireguard keys (public_key will be generated from the private_key)

```
$ vault write wireguard/groups/mygroup/peer1 private_key=$(wg genkey)
```

* Delete the peer

```
$ vault delete wireguard/groups/mygroup/peer1
```

* Generate a configuration suitable for wg-quick

```
$ vault read -field=config wireguard/groups/mygroup/peer1/wg-quick > /etc/wireguard/mygroup.conf
```
### Vault Agent

When combined with Vault Agent templating, this secrets engine will automatically add/remove clients in your Wireguard group.  See [the example agent.conf](/example/agent.conf) for more information.

## Build

Run `make build`
