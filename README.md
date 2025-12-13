# Offline Chat Search (ChatGPT + Claude exports)

This repo turns your exported chat logs into a static website with full‑text search (Pagefind).

It is designed to work offline, because the best place for private conversations is definitely inside more private conversations.

## What it builds

- `site/index.html`: a simple search UI.
- `site/view/...`: one HTML page per conversation, rendered like a chat transcript.
- `site/messages/...`: one HTML page per message (used for Pagefind indexing and ranking).
- `site/pagefind/`: the search index and WASM/JS assets produced by Pagefind.

Search results link to the conversation view and focus the matching message.

## Requirements

- `python3`
- `pagefind` binary (we keep it in `bin/pagefind` in this workspace)

## Build

1) Generate the static site:

`python3 build_site.py`

2) Build the search index:

`bin/pagefind --site site --output-path site/pagefind --force-language en`

3) Open `site/index.html` (or serve `site/` with any static file server).

## Inputs (sensitive)

- `conversations.json` (ChatGPT export)
- `conversations-claude.json` (Claude export)

These (and all generated output) are gitignored on purpose.

