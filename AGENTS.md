General rules. Don't use smileys. Colour is ok.

Keep things simple when possible. Always ensure it runs as fast as possible.

Prefer asking the user for direction and making a plan vs jumping into just starting coding. 

This workspace builds an offline, static search site over exported chat logs.

- Converts `conversations.json` (ChatGPT) and `conversations-claude.json` (Claude) into a static site under `site/`.
- Builds a Pagefind index so `site/index.html` can search individual messages and link into full conversation views.
- Optionally encrypts it at rest and decrypts in the browsers, this allows storing somewhat sensitive information on untrusted or unsecured servers. It does not, and is not, designed to protect against a motivated attacker with server access. They can just update the html/js to send off the key somewhere. But against "at rest" attacks or if the server is compromised.

## Tech

Use `uv` when running python

- Python 3 generator: `build_site.py`
- Pagefind (Rust/WASM) for full‑text search: `bin/pagefind`, output `site/pagefind/`
- Optional JS markdown rendering in search UI: Marked (`vendor/marked.min.js` → `site/assets/marked.min.js`)

