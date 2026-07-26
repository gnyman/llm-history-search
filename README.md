# (static) LLM-History-Search


This is designed to generate a static website which allows you to search your LLM history. 

## Backstory

I created it because I wanted to be able to do a data-export from ChatGPT and Claude, and then delete the data there to avoid it being leaked or being used in the future for training.

Initially this was just something I was going to keep on my machine, but I wanted to be able to access it from anywhere. But even if I trust my VPS host, I did not feel comfortable with having my full chat archives on a "unsecured" server. So I went down the path of extending [pagefind](https://pagefind.app) with [client-side encryption](https://github.com/gnyman/encrypted-pagefind).

## Using

You will need `python3` with `cryptography` , I recommend `uv run --with cryptography` and `pagefind`, optionally [my fork with encryption](https://github.com/gnyman/encrypted-pagefind) if you want that. 

1) Generate the static site:

`uv run --with cryptography build_site.py` (optionally with `--encryption-key "CHANGEME"` )

2) inspect the output in site/ , host locally (`python -m http.server -b 127.0.0.1 808` )or transfer it to a webserver.

When encryption is enabled, the browser stores derived 256-bit decryption keys rather than the
password. “Remember me” keeps them in local storage; otherwise they remain in session storage.

## `--help`

```
usage: build_site.py [-h] [--encryption-key ENCRYPTION_KEY] [--encryption-iterations ENCRYPTION_ITERATIONS]
                     [--encryption-salt ENCRYPTION_SALT] [--encryption-compression {none,gzip,brotli}]
                     [--delete-without-asking] [--pagefind PAGEFIND]

Build the static offline chat search site.

options:
  -h, --help            show this help message and exit
  --encryption-key ENCRYPTION_KEY
                        Encryption key for Pagefind index and conversation pages. Can also use ENCRYPTION_KEY env
                        var.
  --encryption-iterations ENCRYPTION_ITERATIONS
                        PBKDF2 iterations for key derivation. Default: 1000000.
  --encryption-salt ENCRYPTION_SALT
                        Hex-encoded salt for key derivation. If not provided, generates random 16-byte salt.
  --encryption-compression {none,gzip,brotli}
                        Compression before encryption (usualy a good thing, requires 2023+ browser)
  --delete-without-asking
                        Delete site/ directory without prompting (default: ask first).
  --pagefind PAGEFIND   Path to Pagefind binary (defaults to ./pagefind or bin/pagefind).
```

## Compression

When using `--encryption-key`, you can optionally compress the data before encryption to reduce file sizes:

```bash
# No compression (default, maximum browser compatibility)
uv run --with cryptography python build_site.py --encryption-key "CHANGEME"

# Gzip compression using DecompressionStream (most browsers after 2013), reduce the size 70-95%
uv run --with cryptography python build_site.py --encryption-key "CHANGEME" --encryption-compression gzip

# Brotli compression (slightly better compression at the cost of a noticeable slowdown)
uv run --with cryptography python build_site.py --encryption-key "CHANGEME" --encryption-compression brotli
```

## Inputs

Currently it supports two formats

- `conversations.json` (ChatGPT export)
- `conversations-claude.json` (Claude export)

These are the files you get when you do "data export" requests from OpenAI and Claude. It's hard coded to use these two for now.

These (and all generated output) are gitignored on purpose.
