# Self-hosted Nostr relay (DKGKit coordination channel)

A vault's coordination channel is this relay plus the topic tag
`#t = dkgkit:<vault_tag>`. `LiveNostrTransport` connects here to carry DKG, idle
pre-signs, and signing for a whole vault.

## Start

    docker compose -f examples/self-hosted-relay/docker-compose.yml up -d

The relay listens on `ws://127.0.0.1:7777`.

## Use it

    export DKGKIT_TEST_RELAY=ws://127.0.0.1:7777

- Integration test: `cargo test -p dkgkit-nostr --features live -- --ignored`
- Example service: `cargo run -p nostr-transport-service`

## Stop

    docker compose -f examples/self-hosted-relay/docker-compose.yml down
