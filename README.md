# Veil Relay Kit — historical prototype

**Status: historical relay example. Compatibility with the current Veil client has not been established. Do not deploy this kit as a privacy or availability guarantee for current Veil conversations.**

This repository contains a Node.js relay with SQLite message storage, WebSocket and SSE delivery, and optional federation code. It is useful for studying the earlier relay interface. Its API and privacy behavior should be reviewed against the [current Veil privacy model](https://voidly.ai/veil) before any new deployment.

The relay stores ciphertext, but its operator can observe connecting IP addresses, timing, message sizes, and routing identifiers used by this implementation. Running a single relay does not make a user anonymous, and this source alone does not establish support for current Veil features such as drop-box routing or modern client compatibility. Federation needs a separately configured peer secret and an accepted peer relationship; setting environment variables does not grant access to the primary network.

For the current messaging app and its disclosed limits, use [Veil](https://voidly.ai/veil). If this kit is revived, publish a tested compatibility matrix and updated deployment and privacy documentation first.

License: AGPL-3.0-only. See [LICENSE](LICENSE).
