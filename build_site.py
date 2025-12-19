import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path


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
  <title>Chat Search</title>
  <link rel="stylesheet" href="./assets/framework.css">
  <link rel="stylesheet" href="./assets/chat.css">
  <script src="./assets/marked.min.js"></script>
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

  <script type="module">
    import { init, options, search as pagefindSearch } from './pagefind/pagefind.js';

    const searchInput = document.getElementById('search');
    const resultsEl = document.getElementById('results');

    let pagefindReady = null;
    let activeSearchId = 0;
    let debounceTimer = null;
    async function ensureReady() {
      if (!pagefindReady) {
        pagefindReady = (async () => {
          await options({ basePath: './pagefind/' });
          await init();
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

        const href =
          './view/' +
          encodeURIComponent(source) +
          '/' +
          encodeURIComponent(convSafe) +
          '.html#msg-' +
          encodeURIComponent(msgSafe);
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


def write_pages(conversations, site_root: Path) -> tuple[int, int]:
    assets_dir = site_root / "assets"
    view_root = site_root / "view"
    msg_root = site_root / "messages"

    # Clear legacy outputs
    for legacy in (site_root / "simple", site_root / "classless"):
        if legacy.exists():
            shutil.rmtree(legacy)

    for p in (assets_dir, view_root, msg_root):
        if p.exists():
            shutil.rmtree(p)
        p.mkdir(parents=True, exist_ok=True)

    (assets_dir / "chat.css").write_text(CHAT_CSS.strip() + "\n", encoding="utf-8")
    shutil.copyfile(Path("classless.css"), assets_dir / "framework.css")
    marked_src = Path("vendor/marked.min.js")
    if marked_src.exists():
        shutil.copyfile(marked_src, assets_dir / "marked.min.js")

    (site_root / "index.html").write_text(INDEX_HTML, encoding="utf-8")

    message_pages = 0
    conversation_pages = 0

    for conv in conversations:
        conv_id_safe = sanitize_component(conv["id"])

        view_path = view_root / conv["source"] / f"{conv_id_safe}.html"
        view_path.parent.mkdir(parents=True, exist_ok=True)
        framework_href = rel_href(view_path, assets_dir / "framework.css")
        chat_href = rel_href(view_path, assets_dir / "chat.css")
        view_path.write_text(render_conversation_view(conv, framework_href, chat_href), encoding="utf-8")
        conversation_pages += 1

        for msg in conv["messages"]:
            msg_id_safe = sanitize_component(msg["id"])
            msg_path = msg_root / conv["source"] / conv_id_safe / f"{msg_id_safe}.html"
            msg_path.parent.mkdir(parents=True, exist_ok=True)
            msg_path.write_text(render_message_index_page(conv, msg, conv_id_safe, msg_id_safe), encoding="utf-8")
            message_pages += 1

    return conversation_pages, message_pages


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
            except Exception:
                # Compression should never break the build output.
                continue

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

    args = parser.parse_args(argv)

    site_root = Path("site")
    site_root.mkdir(exist_ok=True)

    if not args.brotli_only:
        conversations = []
        chatgpt_path = Path("conversations.json")
        if chatgpt_path.exists():
            conversations.extend(load_chatgpt(chatgpt_path))
        claude_path = Path("conversations-claude.json")
        if claude_path.exists():
            conversations.extend(load_claude(claude_path))

        conversation_pages, message_pages = write_pages(conversations, site_root)
        print(f"Wrote {conversation_pages} conversation pages under site/view")
        print(f"Wrote {message_pages} message pages under site/messages")

    if not args.no_brotli:
        brotli_kind, _ = _detect_brotli()
        wrote = brotli_precompress_site(
            site_root,
            include_messages=bool(args.brotli_all),
            quality=max(0, min(11, int(args.brotli_quality))),
            lgwin=max(10, min(24, int(args.brotli_lgwin))),
        )
        if wrote:
            print(f"Wrote {wrote} Brotli .br files under site/")
        elif args.brotli_only and not brotli_kind:
            print("Brotli not available; no .br files written")


if __name__ == "__main__":
    main(sys.argv[1:])
