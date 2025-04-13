# 🛑 Checkpoint

Checkpoint is a tiny reverse proxy that attempts to block AI by serving a cryptographic challenge.

_This project is a work-in-progress. It works, but has only basic functionality._

## Why?

AI scrapers are everywhere. This will stop them. `robots.txt` won't.

## Features
- Protect your endpoint from AI bots with a cryptographic challenge
- Easy configuration in jsonc
- Support for cloudflare
- Minimal. The waiting page is a single file with no links that weighs 4kB

### Planned features
- Dynamic challenge amount (aka difficulty)
- Detection of token overuse
- Better wait screen
- Better git integration (it's quite rudimentary right now)

## Caveats
If you are using this, it's almost certain search engines will stop indexing your site. Keep this in mind.
