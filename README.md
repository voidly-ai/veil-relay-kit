# Veil Relay Kit

Run your own relay for [Veil](https://voidly.ai/veil) — the one move most
messengers won't let you make. With your own relay, rejoining your IP to
your mailbox takes two operators colluding, not one.

**~5 minutes · runs on a $5 VPS · no logs by design**

## Quick start

```bash
git clone https://github.com/voidly-ai/veil-relay-kit && cd veil-relay-kit
cp .env.example .env          # defaults are fine for standalone use
docker compose up -d --build
```

Put it behind TLS (Veil requires https) — `Caddyfile.example` does it in
one stanza. Then in Veil: **Settings → Privacy → Custom relay** → paste
`https://relay.yourdomain.com`.

## What this relay can and can't see

Honesty first: your relay sees the mailboxes you poll and your IP. It
**cannot** read messages (end-to-end encrypted before they arrive), and it
holds no plaintext, ever. The full disclosure lives in the
[protocol spec](https://voidly.ai/agent-relay-protocol.md).

## Standalone vs federated

By default the kit runs **standalone** — your traffic, your box, no third
party. Set `RELAY_PEER_SECRET` + `RELAY_URL` to federate with the primary
network (optional; peer registration at `/v1/relay/peers`).

## License

AGPL-3.0 — run it anywhere, fork it freely; if you ship a modified relay
as a service, share your changes back.
