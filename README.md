# qqbot-channel

A webhook-first QQ Bot channel for IronClaw WASM channels.

## Current scope

- Inbound: `C2C_MESSAGE_CREATE`, `GROUP_AT_MESSAGE_CREATE`, `AT_MESSAGE_CREATE`, `DIRECT_MESSAGE_CREATE`
- Outbound: text replies for C2C, group, guild channel, and guild direct message
- Status: `Thinking` -> C2C input notify
- Access control: `owner_id`, `allow_from`, DM `pairing`
- Attachments: forwarded as inbound metadata only; outbound media is not implemented yet

## Important runtime tradeoff

IronClaw's current WASM host can inject secrets into URLs and headers, but not JSON request bodies.
QQ Bot access token refresh requires `appId` and `clientSecret` in the POST body.

Because of that, this first version reads `app_id` and `app_secret` from channel config instead of the host secrets store.
That keeps the channel functional today, but it is not the final security model.

## Config example

Use the defaults from `qqbot.capabilities.json` and fill in at least:

```json
{
  "app_id": "your-app-id",
  "app_secret": "your-app-secret",
  "verify_signature": true,
  "reply_to_message": true,
  "dm_policy": "pairing",
  "allow_from": []
}
```

## Repo shape

This repo is laid out like an IronClaw bundled channel source directory:

- `Cargo.toml`
- `src/lib.rs`
- `wit/channel.wit`
- `qqbot.capabilities.json`
- `build.sh`

That means you can either build here directly, or copy this folder into `ironclaw/channels-src/qqbot`.

## Build

```bash
./build.sh
```

If you only want to check the Rust crate logic without producing the final component:

```bash
cargo test
```

## Install

After `./build.sh` succeeds, you get both direct-install files and an artifact bundle:

- `qqbot.wasm`
- `qqbot.capabilities.json`
- `qqbot-wasm32-wasip2.tar.gz`
- `qqbot-wasm32-wasip2.tar.gz.sha256`

Direct file install:

```bash
mkdir -p ~/.ironclaw/channels
cp qqbot.wasm qqbot.capabilities.json ~/.ironclaw/channels/
```

Artifact/bundle install:

- Publish `qqbot-wasm32-wasip2.tar.gz`
- Point the IronClaw channel manifest's `artifacts.wasm32-wasip2.url` at that tarball
- Use the generated `.sha256` value in the manifest checksum field

The compiled WASM component still depends on the vendored [wit/channel.wit](/home/misaka/Code/ironclaw-qqbot/wit/channel.wit:1) contract at build time, but not at runtime.
