import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False


def sanitize_component(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return safe or "item"


def to_iso(ts) -> str:
    if ts is None:
        return ""
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    return str(ts)


def inline_format(text: str) -> str:
    def repl(match):
        return f"<code>{escape(match.group(1))}</code>"

    return re.sub(r"`([^`]+)`", repl, escape(text))


def render_markdown(text: str) -> str:
    """Small markdown-like renderer with fenced code blocks and inline code."""
    lines = text.splitlines()
    out = []
    in_code = False
    code_lang = ""
    code_buf = []
    para_buf = []

    def flush_para():
        if not para_buf:
            return
        joined = "<br>".join(inline_format(line) for line in para_buf)
        out.append(f"<p>{joined}</p>")
        para_buf.clear()

    for line in lines:
        fence = re.match(r"^```(.*)$", line)
        if fence:
            if in_code:
                out.append(
                    f"<pre><code class=\"lang-{escape(code_lang)}\">{escape(chr(10).join(code_buf))}</code></pre>"
                )
                code_buf.clear()
                in_code = False
                code_lang = ""
            else:
                flush_para()
                in_code = True
                code_lang = fence.group(1).strip()
            continue
        if in_code:
            code_buf.append(line)
        else:
            if line.strip() == "":
                flush_para()
            else:
                para_buf.append(line)
    if in_code:
        out.append(f"<pre><code class=\"lang-{escape(code_lang)}\">{escape(chr(10).join(code_buf))}</code></pre>")
    flush_para()
    return "".join(out) if out else f"<p>{escape(text)}</p>"


def derive_encryption_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive 256-bit encryption key using PBKDF2-HMAC-SHA256."""
    if not ENCRYPTION_AVAILABLE:
        raise RuntimeError("Encryption requires 'cryptography' library. Install with: pip install cryptography")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_content(plaintext: bytes, key_bytes: bytes, salt: bytes, iterations: int, compression: str = "none") -> bytes:
    """
    Encrypt content using AES-256-GCM with pre-derived key and optional compression.
    Returns encrypted data in format:
    [12 bytes: "pagefind_e2c" magic]
    [1 byte: compression type (0x00=none, 0x01=gzip, 0x02=brotli)]
    [1 byte: salt length]
    [4 bytes: iterations, big-endian]
    [N bytes: salt]
    [12 bytes: nonce]
    [remaining: AES-256-GCM ciphertext of possibly-compressed data]

    Args:
        plaintext: Data to encrypt
        key_bytes: Pre-derived 256-bit key (use derive_encryption_key)
        salt: Salt used for key derivation (stored in output)
        iterations: Iterations used for key derivation (stored in output)
        compression: Compression type ("none", "gzip", or "brotli")
    """
    if not ENCRYPTION_AVAILABLE:
        raise RuntimeError("Encryption requires 'cryptography' library. Install with: pip install cryptography")

    if len(salt) > 255:
        raise ValueError("Salt length must be <= 255 bytes")

    # Map compression name to byte value
    compression_map = {"none": 0x00, "gzip": 0x01, "brotli": 0x02}
    compression_byte = compression_map[compression]

    # Compress before encrypting if requested
    if compression == "gzip":
        import gzip
        plaintext = gzip.compress(plaintext, compresslevel=6)
    elif compression == "brotli":
        try:
            import brotli
            plaintext = brotli.compress(plaintext, quality=5)
        except ImportError:
            print("WARNING: brotli library not available, falling back to no compression")
            compression_byte = 0x00

    # Generate random 12-byte nonce for AES-GCM
    nonce = secrets.token_bytes(12)

    # Encrypt with AES-256-GCM
    cipher = AESGCM(key_bytes)
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    # Build encrypted format with compression byte
    result = bytearray()
    result.extend(b"pagefind_e2c")  # Magic (12 bytes)
    result.append(compression_byte)  # Compression type (1 byte)
    result.append(len(salt))  # Salt length (1 byte)
    result.extend(struct.pack('>I', iterations))  # Iterations, big-endian (4 bytes)
    result.extend(salt)  # Salt (N bytes)
    result.extend(nonce)  # Nonce (12 bytes)
    result.extend(ciphertext)  # Ciphertext

    return bytes(result)


CHAT_CSS = """
/* Chat-specific layout on top of a classless framework */

.msg { margin: 1rem 0; display: flex; flex-direction: column; }
.meta-line { font-size: 0.9rem; opacity: 0.8; display: flex; gap: 0.6rem; align-items: baseline; }
.meta-line .time { margin-left: auto; white-space: nowrap; }

.msg .bubble {
  max-width: 80ch;
  padding: 0.75rem 0.9rem;
  border-radius: 0.8rem;
  overflow-wrap: anywhere;
  background: rgba(127, 127, 127, 0.08);
  border: 1px solid rgba(127, 127, 127, 0.22);
}
.msg.right { align-items: flex-end; }
.msg.right .bubble { background: rgba(25, 118, 210, 0.10); border-color: rgba(25, 118, 210, 0.25); }
.msg:target .bubble { outline: 2px solid rgba(25, 118, 210, 0.8); }

mark.hit { padding: 0 0.15em; border-radius: 0.2em; }

.results { margin-top: 1rem; }
.results article { padding: 0.75rem 0; border-bottom: 1px solid rgba(127, 127, 127, 0.20); }
.results article:last-child { border-bottom: none; }
.results .meta { opacity: 0.75; margin-top: 0.25rem; }
.results .bubble { margin-top: 0.5rem; max-width: none; }
"""


INDEX_HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; worker-src 'self' blob:; img-src 'self' data:;">
  <title>Chat Search</title>
  <link rel="stylesheet" href="./assets/framework.css">
  <link rel="stylesheet" href="./assets/chat.css">
  <script src="./assets/marked.min.js"></script>
  <style>
    dialog {
      border: 1px solid rgba(127, 127, 127, 0.3);
      border-radius: 0.5rem;
      padding: 1.5rem;
      max-width: 400px;
    }
    dialog::backdrop {
      background: rgba(0, 0, 0, 0.5);
    }
    #key-error {
      color: #c00;
      margin-top: 0.5rem;
      display: none;
    }
    #key-error.show {
      display: block;
    }
    .checkbox-label {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-top: 0.5rem;
      font-size: 0.9em;
      cursor: pointer;
    }
    .checkbox-label input {
      margin: 0;
    }
  </style>
</head>
<body data-pagefind-ignore="all">
  <header>
    <h1>Chat Search</h1>
    <p>Searches individual messages (ChatGPT + Claude)</p>
  </header>

  <main>
    <label>
      Search
      <input id="search" type="search" placeholder="Search messages..." autofocus />
    </label>
    <section class="results" id="results"></section>
  </main>

  <dialog id="key-prompt">
    <h2>Enter Encryption Key</h2>
    <p>This search index is encrypted. Please enter your decryption key:</p>
    <form method="dialog">
      <label>
        Encryption Key
        <input type="password" id="key-input" required autocomplete="off" />
      </label>
      <label class="checkbox-label">
        <input type="checkbox" id="key-remember" checked />
        Remember me on this device
      </label>
      <div id="key-error"></div>
      <button type="submit" id="key-submit">Unlock</button>
    </form>
  </dialog>

  <script type="module">
    import { init, options, search as pagefindSearch, preload } from './pagefind/pagefind.js';

    // Configure marked to escape all raw HTML to prevent XSS
    const renderer = {
      html(text) {
        return text.replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");
      }
    };
    marked.use({ renderer });

    const searchInput = document.getElementById('search');
    const resultsEl = document.getElementById('results');
    const keyPromptDialog = document.getElementById('key-prompt');
    const keyInput = document.getElementById('key-input');
    const keyRemember = document.getElementById('key-remember');
    const keyError = document.getElementById('key-error');
    const keySubmitBtn = document.getElementById('key-submit');

    let pagefindReady = null;
    let activeSearchId = 0;
    let debounceTimer = null;
    const isEncrypted = {is_encrypted};

    async function getEncryptionKey() {
      // Check localStorage first (persistent)
      let stored = localStorage.getItem('chat-search-encryption-key');
      if (stored) return stored;

      // Check sessionStorage second (session only)
      stored = sessionStorage.getItem('chat-search-encryption-key');
      if (stored) return stored;

      // Prompt user for key
      return await promptUserForKey();
    }

    async function promptUserForKey() {
      keyPromptDialog.showModal();
      keyError.textContent = '';
      keyError.classList.remove('show');
      keyInput.value = '';

      return new Promise((resolve) => {
        const handleSubmit = async (e) => {
          e.preventDefault();
          const key = keyInput.value.trim();
          const remember = keyRemember.checked;
          if (!key) return;

          keySubmitBtn.disabled = true;
          keySubmitBtn.textContent = 'Validating...';

          try {
            // Validate key by attempting to initialize Pagefind
            await options({
              encryptionKey: key
            });
            await init();
            await preload('');

            // Success! Store key based on user preference
            if (remember) {
              localStorage.setItem('chat-search-encryption-key', key);
            } else {
              sessionStorage.setItem('chat-search-encryption-key', key);
            }

            keyPromptDialog.close();
            keyPromptDialog.removeEventListener('submit', handleSubmit);
            resolve(key);
          } catch (err) {
            // Wrong key or other error
            keyError.textContent = 'Incorrect key or decryption failed. Please try again.';
            keyError.classList.add('show');
            keySubmitBtn.disabled = false;
            keySubmitBtn.textContent = 'Unlock';
            keyInput.select();
          }
        };

        keyPromptDialog.addEventListener('submit', handleSubmit);
      });
    }

    async function ensureReady() {
      if (!pagefindReady) {
        pagefindReady = (async () => {
          if (isEncrypted) {
            const key = await getEncryptionKey();
            await options({
              encryptionKey: key
            });
            await init();
            await preload('');
          } else {
            await init();
          }
        })();
      }
      await pagefindReady;
    }

    async function runSearch(term, searchId) {
      await ensureReady();
      const res = await pagefindSearch(term);
      if (searchId !== activeSearchId) return;
      resultsEl.innerHTML = '';
      if (!res || res.results.length === 0) {
        resultsEl.textContent = 'No results';
        return;
      }

      const makeUrlWithQuery = (url) => {
        const parts = String(url).split('#');
        const base = parts[0];
        const hash = parts[1] ? ('#' + parts[1]) : '';
        const joiner = base.includes('?') ? '&' : '?';
        return base + joiner + 'q=' + encodeURIComponent(term) + hash;
      };

      const formatTs = (iso) => {
        if (!iso) return '';
        const d = new Date(iso);
        if (Number.isNaN(d.getTime())) return iso;
        return d.toLocaleString();
      };

      const limit = 30;

      const deriveTargetFromUrl = (url) => {
        const raw = String(url || '');
        const noQuery = raw.split('?')[0];
        const path = noQuery.replace(/^\.\//, '').replace(/^\/+/, '');
        const m = path.match(/(?:^|\/)messages\/([^/]+)\/([^/]+)\/([^/]+?)(?:\.html)?$/);
        if (!m) return null;
        return {
          source: m[1] || '',
          convSafe: m[2] || '',
          msgSafe: m[3] || '',
        };
      };

      for (const [idx, r] of res.results.slice(0, limit).entries()) {
        if (searchId !== activeSearchId) return;
        const data = await r.data();
        if (searchId !== activeSearchId) return;
        const meta = data.meta || {};
        const source =
          meta.source ||
          (deriveTargetFromUrl(data.url) ? deriveTargetFromUrl(data.url).source : '') ||
          '';
        const convSafe =
          meta['conversation-id-safe'] ||
          meta.conversation_id_safe ||
          (deriveTargetFromUrl(data.url) ? deriveTargetFromUrl(data.url).convSafe : '') ||
          '';
        const msgSafe =
          meta['message-id-safe'] ||
          meta.message_id_safe ||
          (deriveTargetFromUrl(data.url) ? deriveTargetFromUrl(data.url).msgSafe : '') ||
          '';

        // Build URL: use view-loader if encrypted, direct HTML if not
        let href;
        if (isEncrypted) {
          href = './view-loader.html?source=' + encodeURIComponent(source) +
                 '&conv=' + encodeURIComponent(convSafe) +
                 '#msg-' + encodeURIComponent(msgSafe);
        } else {
          href = './view/' + encodeURIComponent(source) + '/' +
                 encodeURIComponent(convSafe) + '.html#msg-' +
                 encodeURIComponent(msgSafe);
        }
        const finalHref = makeUrlWithQuery(href);

        const el = document.createElement('article');

        const link = document.createElement('a');
        link.href = finalHref;
        link.textContent = meta.title || 'Result';
        el.appendChild(link);

        const metaLine = document.createElement('div');
        metaLine.className = 'meta';
        const bits = [];
        if (meta.source) bits.push('source: ' + meta.source);
        if (meta.author) bits.push('author: ' + meta.author);
        if (meta.timestamp) bits.push('time: ' + formatTs(meta.timestamp));
        metaLine.textContent = bits.join(' · ');
        el.appendChild(metaLine);

        const bubble = document.createElement('div');
        bubble.className = 'bubble';
        if (data.excerpt) {
          // `data.excerpt` contains `<mark>` tags from Pagefind. Marked allows raw HTML by default.
          try {
            bubble.innerHTML = marked.parse(data.excerpt, { breaks: true });
          } catch {
            bubble.innerHTML = data.excerpt;
          }
        }
        el.appendChild(bubble);

        resultsEl.appendChild(el);
      }
    }

    function scheduleSearch() {
      const term = searchInput.value.trim();
      activeSearchId += 1;
      const searchId = activeSearchId;
      if (debounceTimer) clearTimeout(debounceTimer);
      if (term.length === 0) {
        resultsEl.innerHTML = '';
        return;
      }
      debounceTimer = setTimeout(() => {
        runSearch(term, searchId);
      }, 200);
    }

    searchInput.addEventListener('input', scheduleSearch);

    // Prompt for key immediately on page load
    ensureReady();
  </script>
</body>
</html>
"""

VIEW_LOADER_HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Loading Conversation...</title>
  <style>
    body {
      margin: 2rem;
      font-family: system-ui, sans-serif;
    }
    .loading {
      text-align: center;
      padding: 3rem;
    }
    .error {
      color: #c00;
      padding: 2rem;
      border: 1px solid #c00;
      border-radius: 0.5rem;
      background: #fee;
    }
  </style>
</head>
<body>
  <div class="loading" id="loading">
    <p>Decrypting conversation...</p>
  </div>
  <div class="error" id="error" style="display: none;"></div>

  <script type="module">
    import { ChatCrypto } from './assets/crypto.js';

    async function loadEncryptedConversation() {
      const loadingEl = document.getElementById('loading');
      const errorEl = document.getElementById('error');

      try {
        // Parse URL parameters
        const params = new URLSearchParams(location.search);
        const source = params.get('source');
        const conv = params.get('conv');
        const hash = location.hash || '';

        if (!source || !conv) {
          throw new Error('Missing source or conversation ID in URL');
        }

        // Get encryption key from storage
        let key = localStorage.getItem('chat-search-encryption-key');
        if (!key) {
          key = sessionStorage.getItem('chat-search-encryption-key');
        }
        
        if (!key) {
          // Redirect to index to prompt for key
          const returnUrl = encodeURIComponent(location.pathname + location.search + hash);
          window.location.href = './index.html?return=' + returnUrl;
          return;
        }

        // Fetch encrypted conversation file
        const url = `./view/${source}/${conv}.enc.html`;
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`Failed to load conversation: ${response.status} ${response.statusText}`);
        }

        const encryptedData = new Uint8Array(await response.arrayBuffer());

        // Decrypt using ChatCrypto
        const crypto = new ChatCrypto(key);
        const decryptedHtml = await crypto.decryptText(encryptedData);

        // Replace current document with decrypted HTML
        document.open();
        document.write(decryptedHtml);
        document.close();

        // Restore hash if present (for message highlighting)
        if (hash) {
          location.hash = hash;
        }
      } catch (err) {
        loadingEl.style.display = 'none';
        errorEl.style.display = 'block';
        errorEl.innerHTML = `
          <h2>Error Loading Conversation</h2>
          <p>${err.message}</p>
          <p><a href="./index.html">Return to Search</a></p>
        `;
        console.error('Decryption error:', err);
      }
    }

    loadEncryptedConversation();
  </script>
</body>
</html>
"""

CONVERSATION_SCRIPT = """<script>
(function () {
  function formatTimes() {
    document.querySelectorAll('.time[data-iso]').forEach((el) => {
      const iso = el.getAttribute('data-iso');
      if (!iso) return;
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return;
      el.textContent = d.toLocaleString();
    });
  }

  function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
  }

  function highlightIn(container, terms) {
    if (!container || !terms.length) return;
    const pattern = terms
      .slice()
      .sort((a, b) => b.length - a.length)
      .map(escapeRegExp)
      .join('|');
    if (!pattern) return;
    const re = new RegExp(pattern, 'gi');
    const TEXT_ONLY = (window.NodeFilter && window.NodeFilter.SHOW_TEXT) || 4;
    const walker = document.createTreeWalker(container, TEXT_ONLY);
    const nodes = [];
    while (walker.nextNode()) {
      const node = walker.currentNode;
      const parent = node.parentElement;
      if (!parent) continue;
      if (parent.closest('script, style, mark')) continue;
      if (!re.test(node.nodeValue)) continue;
      re.lastIndex = 0;
      nodes.push(node);
    }
    for (const node of nodes) {
      const text = node.nodeValue;
      const frag = document.createDocumentFragment();
      let last = 0;
      let m;
      re.lastIndex = 0;
      while ((m = re.exec(text)) !== null) {
        const start = m.index;
        const end = start + m[0].length;
        if (start > last) frag.appendChild(document.createTextNode(text.slice(last, start)));
        const mark = document.createElement('mark');
        mark.className = 'hit';
        mark.textContent = text.slice(start, end);
        frag.appendChild(mark);
        last = end;
      }
      if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
      node.parentNode.replaceChild(frag, node);
    }
  }

  formatTimes();

  const q = new URLSearchParams(location.search).get('q') || '';
  const terms = (q.match(/"[^"]+"|\\S+/g) || [])
    .map((t) => t.replace(/^"|"$/g, ''))
    .filter((t) => t.length > 0);
  if (!terms.length) return;

  const hash = location.hash || '';
  if (!hash.startsWith('#msg-')) return;
  const target = document.querySelector(hash);
  const bubble = target && target.querySelector('.bubble');
  if (!bubble) return;
  highlightIn(bubble, terms);
})();
</script>"""


def rel_href(from_file: Path, to_file: Path) -> str:
    return os.path.relpath(to_file, start=from_file.parent).replace(os.sep, "/")


def load_chatgpt(path: Path):
    data = json.load(path.open("r", encoding="utf-8"))
    conversations = []
    for idx, conv in enumerate(data):
        conv_id = str(conv.get("conversation_id") or conv.get("id") or f"chatgpt-{idx}")
        conv_title = conv.get("title") or f"ChatGPT Conversation {idx + 1}"
        conv_time = conv.get("create_time")
        mapping = conv.get("mapping") or {}
        current_node = conv.get("current_node")
        chain = []
        if current_node and current_node in mapping:
            node_id = current_node
            seen = set()
            while node_id and node_id not in seen and node_id in mapping:
                seen.add(node_id)
                node = mapping[node_id]
                chain.append(node)
                node_id = node.get("parent")
            chain.reverse()
        else:
            chain = list(mapping.values())

        msgs = []
        for node in chain:
            msg = node.get("message")
            if not msg:
                continue
            content = msg.get("content") or {}
            if content.get("content_type") != "text":
                continue
            parts = content.get("parts") or []
            text = " ".join(p for p in parts if isinstance(p, str)).strip()
            if not text:
                continue
            author = (msg.get("author") or {}).get("role") or "unknown"
            ts = msg.get("create_time") or conv_time
            msgs.append(
                {
                    "id": msg.get("id") or node.get("id") or f"msg-{len(msgs)}",
                    "author": author,
                    "text": text,
                    "timestamp": to_iso(ts),
                }
            )
        conversations.append(
            {
                "id": conv_id,
                "title": conv_title,
                "timestamp": to_iso(conv_time),
                "source": "chatgpt",
                "messages": msgs,
            }
        )
    return conversations


def load_claude(path: Path):
    data = json.load(path.open("r", encoding="utf-8"))
    conversations = []
    for idx, conv in enumerate(data):
        conv_id = str(conv.get("uuid") or f"claude-{idx}")
        conv_title = conv.get("name") or conv.get("summary") or f"Claude Conversation {idx + 1}"
        conv_time = conv.get("created_at")
        msgs = []
        for msg in conv.get("chat_messages", []):
            text = msg.get("text") or ""
            if not text.strip():
                continue
            author = msg.get("sender") or (msg.get("participant") or {}).get("user_type") or "unknown"
            ts = msg.get("created_at") or conv_time
            msgs.append(
                {
                    "id": msg.get("uuid") or f"msg-{len(msgs)}",
                    "author": author,
                    "text": text.strip(),
                    "timestamp": to_iso(ts),
                }
            )
        msgs.sort(key=lambda m: (m["timestamp"] or "", m["id"]))
        conversations.append(
            {
                "id": conv_id,
                "title": conv_title,
                "timestamp": to_iso(conv_time),
                "source": "claude",
                "messages": msgs,
            }
        )
    return conversations


def write_message_index_pages(conversations, root_dir: Path) -> int:
    """Write message index pages for Pagefind (always unencrypted)."""
    msg_root = root_dir / "messages"
    msg_root.mkdir(parents=True, exist_ok=True)

    message_pages = 0
    total_messages = sum(len(conv["messages"]) for conv in conversations)

    print(f"Generating message index pages for Pagefind...")
    for conv in conversations:
        conv_id_safe = sanitize_component(conv["id"])

        for msg in conv["messages"]:
            msg_id_safe = sanitize_component(msg["id"])
            msg_path = msg_root / conv["source"] / conv_id_safe / f"{msg_id_safe}.html"
            msg_path.parent.mkdir(parents=True, exist_ok=True)
            msg_path.write_text(render_message_index_page(conv, msg, conv_id_safe, msg_id_safe), encoding="utf-8")
            message_pages += 1

            if message_pages % 1000 == 0:
                print(f"\r  [{message_pages}/{total_messages}] message pages written...", end='', flush=True)

    print()  # Final newline after progress updates
    return message_pages


def write_conversation_pages(conversations, site_root: Path, encryption_key: str = None, encryption_salt: bytes = None, encryption_iterations: int = 100000, encryption_compression: str = "none") -> int:
    """Write conversation view pages (encrypted if key provided)."""
    assets_dir = site_root / "assets"
    view_root = site_root / "view"
    view_root.mkdir(parents=True, exist_ok=True)

    conversation_pages = 0
    total_conversations = len(conversations)

    # Derive encryption key once if encrypting (expensive PBKDF2 operation)
    derived_key = None
    if encryption_key:
        print(f"Deriving encryption key (PBKDF2 with {encryption_iterations:,} iterations)...")
        derived_key = derive_encryption_key(encryption_key, encryption_salt, encryption_iterations)
        print(f"Generating encrypted conversation pages...")
    else:
        print(f"Generating conversation pages...")

    for idx, conv in enumerate(conversations, 1):
        conv_id_safe = sanitize_component(conv["id"])

        # Generate conversation view HTML
        framework_href = rel_href(view_root / conv["source"] / f"{conv_id_safe}.html", assets_dir / "framework.css")
        chat_href = rel_href(view_root / conv["source"] / f"{conv_id_safe}.html", assets_dir / "chat.css")
        conversation_html = render_conversation_view(conv, framework_href, chat_href)

        # Write conversation view (encrypted if key provided)
        if encryption_key:
            view_path = view_root / conv["source"] / f"{conv_id_safe}.enc.html"
            view_path.parent.mkdir(parents=True, exist_ok=True)
            encrypted_data = encrypt_content(
                conversation_html.encode('utf-8'),
                derived_key,  # Use pre-derived key (fast)
                encryption_salt,
                encryption_iterations,
                encryption_compression
            )
            view_path.write_bytes(encrypted_data)
        else:
            view_path = view_root / conv["source"] / f"{conv_id_safe}.html"
            view_path.parent.mkdir(parents=True, exist_ok=True)
            view_path.write_text(conversation_html, encoding="utf-8")
        conversation_pages += 1

        if conversation_pages % 500 == 0:
            print(f"\r  [{conversation_pages}/{total_conversations}] conversation pages written...", end='', flush=True)

    print()  # Final newline after progress updates
    return conversation_pages


def setup_assets(site_root: Path, encryption_enabled: bool = False):
    """Set up assets directory with CSS, JS, and templates."""
    assets_dir = site_root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    (assets_dir / "chat.css").write_text(CHAT_CSS.strip() + "\n", encoding="utf-8")
    shutil.copyfile(Path("classless.css"), assets_dir / "framework.css")
    marked_src = Path("vendor/marked.min.js")
    if marked_src.exists():
        shutil.copyfile(marked_src, assets_dir / "marked.min.js")

    # Copy crypto.js for client-side decryption
    crypto_src = Path("crypto.js")
    if crypto_src.exists():
        shutil.copyfile(crypto_src, assets_dir / "crypto.js")

    # Render index.html with encryption flag
    index_html = INDEX_HTML.replace('{is_encrypted}', 'true' if encryption_enabled else 'false')
    (site_root / "index.html").write_text(index_html, encoding="utf-8")
    (site_root / "view-loader.html").write_text(VIEW_LOADER_HTML, encoding="utf-8")


def render_conversation_view(conv: dict, framework_css_href: str, chat_css_href: str) -> str:
    def render_bubble(m):
        side = "right" if m["author"] in ("user", "human") else "left"
        role_label = "You" if m["author"] in ("user", "human") else m["author"]
        content_html = render_markdown(m["text"])
        msg_id_safe = sanitize_component(m["id"])
        iso = m.get("timestamp", "")
        return f"""
        <div class="msg {side}" id="msg-{escape(msg_id_safe)}">
          <div class="meta-line"><span class="role">{escape(role_label)}</span><span class="time" data-iso="{escape(iso)}">{escape(iso)}</span></div>
          <div class="bubble">{content_html}</div>
        </div>
        """

    conversation_html = "\n".join(render_bubble(m) for m in conv["messages"])
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{escape(conv["title"])}</title>
  <link rel="stylesheet" href="{escape(framework_css_href)}">
  <link rel="stylesheet" href="{escape(chat_css_href)}">
</head>
<body data-pagefind-ignore="all">
  <header>
    <h1>{escape(conv["title"])}</h1>
    <nav><a href="../../index.html">Search</a></nav>
    <p>
      Source: {escape(conv["source"])} · Conversation: {escape(conv["id"])} · Created:
      <span class="time" data-iso="{escape(conv.get("timestamp",""))}">{escape(conv.get("timestamp",""))}</span>
    </p>
  </header>

  <main>
    {conversation_html}
  </main>
  {CONVERSATION_SCRIPT}
</body>
</html>
"""


def render_message_index_page(conv: dict, msg: dict, conv_id_safe: str, msg_id_safe: str) -> str:
    target_meta = {
        "title": conv["title"],
        "source": conv["source"],
        "conversation-id": conv["id"],
        "conversation-id-safe": conv_id_safe,
        "author": msg["author"],
        "timestamp": msg.get("timestamp", ""),
        "message-id-safe": msg_id_safe,
    }
    meta_tags = "\n  ".join(
        f'<div data-pagefind-meta="{k}">{escape(str(v))}</div>' for k, v in target_meta.items()
    )
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{escape(conv["title"])} - {escape(msg["id"])}</title>
</head>
<body>
  <div hidden>
  {meta_tags}
  </div>
  <article data-pagefind-body>
    <pre>{escape(msg["text"])}</pre>
  </article>
</body>
</html>
"""

def _detect_brotli():
    try:
        import brotli  # type: ignore

        return ("python", brotli)
    except Exception:
        pass

    try:
        import brotlicffi as brotli  # type: ignore

        return ("python", brotli)
    except Exception:
        pass

    exe = shutil.which("brotli")
    if exe:
        return ("cli", exe)
    return (None, None)


def _should_brotli_path(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name.endswith(".br"):
        return False
    if path.name.endswith(".gz"):
        return False
    if path.name.startswith("."):
        return False

    suffix = path.suffix.lower()
    if suffix in {".html", ".css", ".js", ".json", ".txt", ".svg", ".xml", ".map"}:
        return True
    if suffix in {".wasm"}:
        return True

    # Pagefind outputs
    if path.name.endswith(".pf_meta") or path.name.endswith(".pf_fragment"):
        return True
    if path.name.endswith(".pagefind"):
        return True

    return False


def _brotli_mode_for_path(brotli_mod, path: Path):
    suffix = path.suffix.lower()
    is_text = suffix in {".html", ".css", ".js", ".json", ".txt", ".svg", ".xml", ".map"}
    if is_text and hasattr(brotli_mod, "MODE_TEXT"):
        return brotli_mod.MODE_TEXT
    if hasattr(brotli_mod, "MODE_GENERIC"):
        return brotli_mod.MODE_GENERIC
    return None


def _maybe_write_brotli_file(
    src: Path,
    quality: int,
    lgwin: int,
    brotli_kind,
    brotli_impl,
    *,
    min_savings_ratio: float = 0.01,
) -> bool:
    dst = src.with_name(src.name + ".br")

    try:
        src_stat = src.stat()
    except FileNotFoundError:
        return False

    if dst.exists():
        try:
            dst_stat = dst.stat()
            if dst_stat.st_mtime >= src_stat.st_mtime and dst_stat.st_size > 0:
                return False
        except FileNotFoundError:
            pass

    tmp = dst.with_name(dst.name + ".tmp")
    if tmp.exists():
        tmp.unlink()

    if brotli_kind == "python":
        brotli_mod = brotli_impl
        mode = _brotli_mode_for_path(brotli_mod, src)
        compressor_kwargs = {"quality": quality, "lgwin": lgwin}
        if mode is not None:
            compressor_kwargs["mode"] = mode
        compressor = brotli_mod.Compressor(**compressor_kwargs)

        with src.open("rb") as f_in, tmp.open("wb") as f_out:
            while True:
                chunk = f_in.read(256 * 1024)
                if not chunk:
                    break
                out = compressor.process(chunk)
                if out:
                    f_out.write(out)
            tail = compressor.finish()
            if tail:
                f_out.write(tail)
    elif brotli_kind == "cli":
        exe = brotli_impl
        # -f: overwrite, -q: quality, --lgwin: window size
        subprocess.run(
            [exe, "-f", "-q", str(quality), "--lgwin", str(lgwin), "-o", str(tmp), str(src)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        return False

    try:
        tmp_size = tmp.stat().st_size
    except FileNotFoundError:
        return False

    if tmp_size <= 0:
        tmp.unlink(missing_ok=True)
        return False

    # Only keep if it actually shrinks meaningfully.
    if tmp_size >= int(src_stat.st_size * (1.0 - min_savings_ratio)):
        tmp.unlink(missing_ok=True)
        return False

    tmp.replace(dst)
    try:
        os.utime(dst, (src_stat.st_atime, src_stat.st_mtime))
    except Exception:
        pass
    return True


def brotli_precompress_site(
    site_root: Path,
    *,
    include_messages: bool,
    quality: int,
    lgwin: int,
) -> int:
    brotli_kind, brotli_impl = _detect_brotli()
    if not brotli_kind:
        return 0

    roots = [site_root / "assets", site_root / "pagefind", site_root / "view"]
    if include_messages:
        roots.append(site_root / "messages")

    wrote = 0
    seen = set()
    # Only consider files directly under site/ at the top level (e.g., site/index.html).
    if site_root.exists():
        for path in sorted(site_root.iterdir()):
            if not path.is_file():
                continue
            if not _should_brotli_path(path):
                continue
            seen.add(path)
            try:
                if _maybe_write_brotli_file(path, quality, lgwin, brotli_kind, brotli_impl):
                    wrote += 1
            except Exception:
                continue

    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            candidates = [root]
        else:
            candidates = sorted(root.rglob("*"))
        for path in candidates:
            if not _should_brotli_path(path):
                continue
            if path in seen:
                continue
            seen.add(path)
            try:
                if _maybe_write_brotli_file(path, quality, lgwin, brotli_kind, brotli_impl):
                    wrote += 1
                    if wrote % 500 == 0:
                        print(f"\r  Compressed {wrote} files...", end='', flush=True)
            except Exception:
                # Compression should never break the build output.
                continue

    if wrote > 0:
        print()  # Final newline after progress
    return wrote


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Build the static offline chat search site.")
    parser.add_argument(
        "--brotli-only",
        action="store_true",
        help="Only generate .br files for existing site/ output (no page regeneration).",
    )
    parser.add_argument(
        "--no-brotli",
        action="store_true",
        help="Disable Brotli precompression even if Brotli is available.",
    )
    parser.add_argument(
        "--brotli-all",
        action="store_true",
        help="Also Brotli-compress site/messages/ (usually unnecessary and slower).",
    )
    parser.add_argument(
        "--brotli-quality",
        type=int,
        default=int(os.environ.get("BROTLI_QUALITY", "5")),
        help="Brotli quality (0-11). Default: 5 or $BROTLI_QUALITY.",
    )
    parser.add_argument(
        "--brotli-lgwin",
        type=int,
        default=int(os.environ.get("BROTLI_LGWIN", "22")),
        help="Brotli window size (10-24). Default: 22 or $BROTLI_LGWIN.",
    )
    parser.add_argument(
        "--encryption-key",
        type=str,
        help="Encryption key for Pagefind index and conversation pages. Can also use ENCRYPTION_KEY env var.",
    )
    parser.add_argument(
        "--encryption-iterations",
        type=int,
        default=100000,
        help="PBKDF2 iterations for key derivation. Default: 100000.",
    )
    parser.add_argument(
        "--encryption-salt",
        type=str,
        help="Hex-encoded salt for key derivation. If not provided, generates random 16-byte salt.",
    )
    parser.add_argument(
        "--encryption-compression",
        type=str,
        choices=["none", "gzip", "brotli"],
        default="none",
        help="Compression before encryption (none=maximum compatibility, gzip=74%% smaller, brotli=78%% smaller). Requires modern browsers (Chrome 80+, Firefox 68+, Safari 16.4+).",
    )
    parser.add_argument(
        "--delete-without-asking",
        action="store_true",
        help="Delete site/ directory without prompting (default: ask first).",
    )
    parser.add_argument(
        "--pagefind",
        type=str,
        help="Path to Pagefind binary (defaults to ./pagefind or bin/pagefind).",
    )

    args = parser.parse_args(argv)

    # Get encryption key (env var takes precedence)
    encryption_key = os.environ.get("ENCRYPTION_KEY") or args.encryption_key
    encryption_iterations = args.encryption_iterations
    encryption_compression = args.encryption_compression if encryption_key else "none"

    # Validate encryption key
    if encryption_key == "CHANGEME":
        print("ERROR: You must change the encryption key from 'CHANGEME' to your own secure key.")
        print("Use a strong, unique password for --encryption-key")
        sys.exit(1)

    # Generate or parse salt
    encryption_salt = None
    if encryption_key:
        if not ENCRYPTION_AVAILABLE:
            print("ERROR: Encryption requested but 'cryptography' library not available.")
            print("Install with: pip install cryptography")
            sys.exit(1)

        if args.encryption_salt:
            try:
                encryption_salt = bytes.fromhex(args.encryption_salt)
            except ValueError:
                print("ERROR: --encryption-salt must be a hex-encoded string")
                sys.exit(1)
        else:
            encryption_salt = secrets.token_bytes(16)
            print(f"Generated random salt: {encryption_salt.hex()}")

    site_root = Path("site")

    if not args.brotli_only:
        # Clean slate: remove entire site directory
        if site_root.exists():
            if not args.delete_without_asking:
                response = input(f"Delete existing {site_root}/ directory? [y/N]: ").strip().lower()
                if response not in ('y', 'yes'):
                    print("Aborted.")
                    sys.exit(0)
            shutil.rmtree(site_root)
            print(f"Deleted {site_root}/")
        site_root.mkdir(parents=True, exist_ok=True)

        # Step 1: Load conversations
        print("\n=== Step 1/5: Loading conversations ===")
        conversations = []
        chatgpt_path = Path("conversations.json")
        if chatgpt_path.exists():
            conversations.extend(load_chatgpt(chatgpt_path))
        claude_path = Path("conversations-claude.json")
        if claude_path.exists():
            conversations.extend(load_claude(claude_path))
        print(f"Loaded {len(conversations)} conversations")

        # Step 2: Set up assets and templates
        print("\n=== Step 2/5: Setting up assets ===")
        setup_assets(site_root, encryption_enabled=bool(encryption_key))
        print("Assets and templates ready")

        # Step 3: Generate message index pages (for Pagefind)
        print("\n=== Step 3/5: Generating message index pages ===")
        # Use a temporary directory for plaintext indexing to avoid leaking them in site/
        temp_index_root = Path("temp_index_build")
        if temp_index_root.exists():
            shutil.rmtree(temp_index_root)
        temp_index_root.mkdir(parents=True, exist_ok=True)
        
        try:
            message_pages = write_message_index_pages(conversations, temp_index_root)
            print(f"Wrote {message_pages} message index pages to temporary directory")

            # Step 4: Run Pagefind to build search index
            print("\n=== Step 4/5: Building search index with Pagefind ===")
            pagefind_bin = None
            if args.pagefind:
                candidate = Path(args.pagefind).expanduser()
                if candidate.exists() and candidate.is_file():
                    pagefind_bin = candidate
                else:
                    print(f"ERROR: --pagefind binary not found at {candidate}")
                    sys.exit(1)
            else:
                for candidate in [Path("pagefind"), Path("./pagefind"), Path("bin/pagefind")]:
                    if candidate.exists() and candidate.is_file():
                        pagefind_bin = candidate
                        break

            if not pagefind_bin:
                print("WARNING: pagefind binary not found, skipping index generation")
            else:
                # Ensure output directory exists
                (site_root / "pagefind").mkdir(parents=True, exist_ok=True)

                # Use absolute path to ensure subprocess can find the binary
                # We index the temporary directory, but output to the real site directory
                cmd = [
                    str(pagefind_bin.resolve()),
                    "--site", str(temp_index_root),
                    "--output-path", str(site_root / "pagefind"),
                    "--force-language", "en"
                ]
                if encryption_key:
                    cmd.extend(["--encryption-key", encryption_key])
                    cmd.extend(["--encryption-iterations", str(encryption_iterations)])
                    if args.encryption_salt:
                        cmd.extend(["--encryption-salt", args.encryption_salt])
                    else:
                        cmd.extend(["--encryption-salt", encryption_salt.hex()])

                print(f"Running: {pagefind_bin.name} --site {temp_index_root} --output-path site/pagefind ...")
                try:
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    if result.stdout:
                        print(result.stdout)
                    if encryption_key:
                        print("Pagefind encrypted index generated successfully")
                    else:
                        print("Pagefind index generated successfully")
                except subprocess.CalledProcessError as e:
                    print(f"ERROR: Pagefind failed with exit code {e.returncode}")
                    if e.stderr:
                        print(e.stderr)
                    sys.exit(1)
                except (FileNotFoundError, PermissionError, OSError) as e:
                    print(f"ERROR: Failed to run pagefind binary: {e}")
                    print(f"Binary location: {pagefind_bin.resolve()}")
                    print("\nIf on macOS and downloaded the binary, you may need to remove quarantine:")
                    print(f"  xattr -d com.apple.quarantine {pagefind_bin}")
                    sys.exit(1)

        finally:
            # Always clean up temporary plaintext files
            if temp_index_root.exists():
                shutil.rmtree(temp_index_root)
                print("Cleaned up temporary plaintext message pages")

        if encryption_key:
            print("\n=== Step 5/5: Generating encrypted conversation pages ===")
        else:
            print("\n=== Step 5/5: Generating conversation pages ===")

        # Step 5: Generate conversation pages (encrypted if key provided)
        conversation_pages = write_conversation_pages(
            conversations,
            site_root,
            encryption_key=encryption_key,
            encryption_salt=encryption_salt,
            encryption_iterations=encryption_iterations,
            encryption_compression=encryption_compression
        )
        if encryption_key:
            print(f"Wrote {conversation_pages} encrypted conversation pages")
        else:
            print(f"Wrote {conversation_pages} conversation pages")

        print(f"\n✓ Build complete! Output in site/")
    else:
        # For brotli-only mode, site must already exist
        if not site_root.exists():
            print("ERROR: site/ directory not found (required for --brotli-only)")
            sys.exit(1)

    if not args.no_brotli:
        brotli_kind, _ = _detect_brotli()
        if brotli_kind:
            print("\nCompressing with Brotli...")
        wrote = brotli_precompress_site(
            site_root,
            include_messages=bool(args.brotli_all),
            quality=max(0, min(11, int(args.brotli_quality))),
            lgwin=max(10, min(24, int(args.brotli_lgwin))),
        )
        if wrote:
            print(f"Wrote {wrote} Brotli .br files")
        elif args.brotli_only and not brotli_kind:
            print("Brotli not available; no .br files written")


if __name__ == "__main__":
    main(sys.argv[1:])
