# 🛑 Checkpoint

Checkpoint is a tiny reverse proxy that attempts to block AI by serving a cryptographic challenge.

_This project is a work-in-progress. It works, but has only basic functionality._

## Why?

AI scrapers are everywhere. This will stop them. `robots.txt` won't.

## Features
- Protect your endpoint from AI bots with a cryptographic challenge
- Easy configuration in jsonc
- Support for cloudflare
- Support for IP-Range based rules (both ipv4 and ipv6)
- Support for async (multithreaded) request handling
- Minimal. The waiting page is tiny and light on network usage.

### Planned features
- Dynamic challenge amount (aka difficulty) based on traffic
- Detection of token overuse
- Better wait screen
- Better git integration (it's quite rudimentary right now)

## Caveats
If you are using this, it's almost certain search engines will stop indexing your site. Keep this in mind.

## Setup guide

1. Clone and build this repo. You will need `openssl`, `g++>=12`, `re2`, and deps for `pistache`, `fmt` and `tinylates`.
2. Create a `config.jsonc`. An example one is in `example/`.
3. Adjust the config to your needs. Options are documented with comments in the example config.
4. Set up your IP rules if you want. These allow you to set up IPs that are automatically blocked, or allowed to access without a challenge. This is useful for e.g. search engine scrapers. Some IP ranges can be found in `example/index_bots.jsonc`.
5. Run checkpoint with your config: `./build/checkpoint -c config.jsonc`. How you run it long-term as a service is up to you.
