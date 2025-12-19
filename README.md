# Offline Chat Search (ChatGPT + Claude exports)

This repo turns your exported chat logs into a static website with full‑text search (Pagefind).

It is designed to work offline, because the best place for private conversations is definitely inside more private conversations.

## What it builds

- `site/index.html`: a search UI (Classless.css).
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

3) (Optional) Precompress with Brotli (writes `.br` files if Brotli is available, note, these won't be served over plain http):

`python3 build_site.py --brotli-only`

(note2: you can also use `--brotli-all` to compress conversations also)

4) Open `site/index.html` (or serve `site/` with any static file server).

## Inputs (sensitive)

- `conversations.json` (ChatGPT export)
- `conversations-claude.json` (Claude export)

These (and all generated output) are gitignored on purpose, unless you like splurging your personal data all over the internet you should not include them in your git repo.
