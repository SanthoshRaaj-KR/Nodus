/* =====================================================================
   The "ask the graph" popup: one floating button, bottom-right, on every
   page. Talks to /api/chat/<ref>, where <ref> is whichever repository the
   picker at / sent the browser here for (stored under WORKSPACE_KEY) --
   falling back to /api/chat/default, the one workspace the chat router
   auto-provisions over every service currently in the graph, for anyone
   who lands on a page directly without going through the picker.

   Self-contained on purpose, like chrome.js: one file, injected on every
   page, owning its own markup and styles so the page templates stay free
   of anything chat-specific.
   ===================================================================== */
"use strict";

(function () {
  const STYLE_ID = "chatw-style";
  const SESSION_KEY = "blastradius.chat.session";
  const WORKSPACE_KEY = "nodus.workspace";

  function workspaceRef() {
    try {
      return localStorage.getItem(WORKSPACE_KEY) || "default";
    } catch (e) {
      return "default";
    }
  }

  function sessionId() {
    try {
      let id = sessionStorage.getItem(SESSION_KEY);
      if (!id) {
        id = (crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()));
        sessionStorage.setItem(SESSION_KEY, id);
      }
      return id;
    } catch (e) {
      return "default";
    }
  }

  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      .chatw-launch {
        position: fixed; right: 22px; bottom: 22px; z-index: 60;
        display: flex; align-items: center; gap: 8px;
        padding: 0 18px 0 16px; height: 46px; border: 1px solid var(--line);
        border-radius: var(--r-pill); background: var(--accent); color: var(--ink-on);
        font: 600 13.5px/1 var(--sans); letter-spacing: -.01em; cursor: pointer;
        box-shadow: var(--shadow-2); transition: transform .12s ease, box-shadow .12s ease;
      }
      .chatw-launch:hover { transform: translateY(-1px); }
      .chatw-launch:focus-visible { outline: none; box-shadow: var(--shadow-2), var(--ring); }
      .chatw-launch .gl { font-size: 16px; line-height: 1; }
      .chatw-launch.open { display: none; }

      .chatw-panel {
        position: fixed; right: 22px; bottom: 22px; z-index: 60;
        width: min(380px, calc(100vw - 32px)); height: min(560px, calc(100vh - 100px));
        display: none; flex-direction: column; overflow: hidden;
        background: var(--surface-0); border: 1px solid var(--line);
        border-radius: var(--r-lg); box-shadow: var(--shadow-2);
        font-family: var(--sans);
      }
      .chatw-panel.open { display: flex; }

      .chatw-head {
        display: flex; align-items: center; gap: 8px;
        padding: 12px 12px 12px 16px; border-bottom: 1px solid var(--line);
        background: var(--surface-1);
      }
      .chatw-head .ttl { font: 600 14px/1.2 var(--sans); color: var(--ink-1); }
      .chatw-head .sub { font: 500 11px/1.2 var(--mono); color: var(--ink-3); }
      .chatw-head .spacer { flex: 1; }
      .chatw-close {
        width: 28px; height: 28px; display: grid; place-items: center;
        border-radius: var(--r-sm); border: none; background: transparent;
        color: var(--ink-3); cursor: pointer; font-size: 15px; line-height: 1;
      }
      .chatw-close:hover { background: var(--surface-2); color: var(--ink-1); }

      .chatw-body {
        flex: 1; overflow-y: auto; padding: 12px 14px;
        display: flex; flex-direction: column; gap: 10px;
        background: var(--surface-0);
      }
      .chatw-msg { max-width: 88%; font: 400 13px/1.45 var(--sans); white-space: pre-wrap; word-wrap: break-word; }
      .chatw-msg.user {
        align-self: flex-end; background: var(--tint-accent); color: var(--ink-1);
        padding: 8px 11px; border-radius: var(--r-md) var(--r-md) 2px var(--r-md);
      }
      .chatw-msg.bot {
        align-self: flex-start; background: var(--surface-2); color: var(--ink-1);
        padding: 8px 11px; border-radius: var(--r-md) var(--r-md) var(--r-md) 2px;
      }
      .chatw-msg.err { color: var(--threat); }
      .chatw-msg.pending { color: var(--ink-3); font-style: italic; }

      /* Rendered markdown. The agent is told to answer in short markdown, so
         a bubble carrying real block elements drops the pre-wrap the plain
         ones need -- keeping both would double every gap. */
      .chatw-msg.md { white-space: normal; min-width: 0; }
      .chatw-msg.md > :first-child { margin-top: 0; }
      .chatw-msg.md > :last-child { margin-bottom: 0; }
      .chatw-msg.md p { margin: 0 0 8px; }
      .chatw-msg.md ul, .chatw-msg.md ol { margin: 0 0 8px; padding-left: 17px; }
      .chatw-msg.md li { margin: 2px 0; }
      .chatw-msg.md li::marker { color: var(--ink-3); }
      .chatw-msg.md h1, .chatw-msg.md h2, .chatw-msg.md h3,
      .chatw-msg.md h4, .chatw-msg.md h5, .chatw-msg.md h6 {
        font: 600 13px/1.35 var(--sans); margin: 10px 0 5px; color: var(--ink-1);
      }
      .chatw-msg.md strong { font-weight: 650; color: var(--ink-1); }
      .chatw-msg.md em { font-style: italic; }
      .chatw-msg.md del { opacity: .65; }
      .chatw-msg.md a { color: var(--accent); text-decoration: underline; }
      .chatw-msg.md code {
        font: 500 11.5px/1.4 var(--mono); background: var(--surface-0);
        border: 1px solid var(--line); border-radius: 4px; padding: 0 4px;
        overflow-wrap: anywhere;
      }
      /* A lockfile path or a stack frame is wider than a 380px panel, so the
         block scrolls itself rather than pushing the panel sideways. */
      .chatw-msg.md pre {
        margin: 0 0 8px; padding: 8px 10px; overflow-x: auto;
        background: var(--surface-0); border: 1px solid var(--line);
        border-radius: var(--r-sm);
      }
      .chatw-msg.md pre code {
        border: none; background: none; padding: 0; overflow-wrap: normal;
        white-space: pre; display: block;
      }
      .chatw-msg.md blockquote {
        margin: 0 0 8px; padding-left: 9px;
        border-left: 2px solid var(--line); color: var(--ink-2);
      }
      .chatw-msg.md hr { border: none; border-top: 1px solid var(--line); margin: 10px 0; }

      /* Which tool the agent reached for, shown while the answer is still
         empty so a multi-second wait says what it is doing. */
      .chatw-tool {
        align-self: flex-start; color: var(--ink-3);
        font: 500 11px/1.4 var(--mono); padding: 0 2px;
      }
      /* Layer 3 of the guardrails, surfaced rather than swallowed: a spec the
         answer named that this repository has never resolved. */
      .chatw-flag {
        align-self: flex-start; max-width: 88%; color: var(--warn);
        font: 500 11.5px/1.45 var(--sans); padding: 6px 9px;
        border: 1px solid var(--line); border-radius: var(--r-sm);
        background: var(--surface-1);
      }

      .chatw-empty { color: var(--ink-3); font: 400 12.5px/1.5 var(--sans); padding: 4px 2px; }
      .chatw-starters { display: flex; flex-direction: column; gap: 6px; margin-top: 10px; }
      .chatw-starter {
        text-align: left; border: 1px solid var(--line); background: var(--surface-1);
        color: var(--ink-2); border-radius: var(--r-md); padding: 7px 10px;
        font: 500 12px/1.35 var(--sans); cursor: pointer;
      }
      .chatw-starter:hover { background: var(--surface-2); color: var(--ink-1); }

      .chatw-form {
        display: flex; gap: 8px; padding: 10px 12px; border-top: 1px solid var(--line);
        background: var(--surface-1);
      }
      .chatw-input {
        flex: 1; resize: none; border: 1px solid var(--line); border-radius: var(--r-md);
        background: var(--surface-0); color: var(--ink-1); font: 400 13px/1.4 var(--sans);
        padding: 8px 10px; max-height: 84px;
      }
      .chatw-input:focus { outline: none; box-shadow: var(--ring); }
      .chatw-send {
        border: none; border-radius: var(--r-md); background: var(--accent); color: var(--ink-on);
        font: 600 12.5px/1 var(--sans); padding: 0 14px; cursor: pointer;
      }
      .chatw-send:disabled { opacity: .5; cursor: default; }

      @media (max-width: 480px) {
        .chatw-panel { right: 10px; left: 10px; bottom: 10px; width: auto; height: min(72vh, 560px); }
        .chatw-launch { right: 14px; bottom: 14px; }
      }
    `;
    document.head.appendChild(style);
  }

  /* ===================================================================
     Markdown, rendered here rather than pulled in.

     The agent is instructed to answer in short markdown -- a sentence or
     two, then a compact list -- so putting its output in `textContent`
     showed people literal `**vite@5.4.21**`. This covers exactly what
     that instruction produces: emphasis, inline code, fences, lists,
     headings, quotes, rules and links. A full CommonMark library is a
     larger dependency than the whole widget, and this file is
     self-contained on purpose.

     Everything is escaped BEFORE any markup is generated, so the only
     tags that can reach the DOM are the ones below. That matters more
     than usual here: the text being rendered is model output, and a
     tool result inside it is ultimately registry data we did not write.
     =================================================================== */

  const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

  function esc(text) {
    return String(text == null ? "" : text).replace(/[&<>"']/g, (ch) => ESCAPES[ch]);
  }

  function inlineMd(escaped) {
    // Inline code is lifted out first and put back last, so nothing below
    // rewrites the inside of a span that is meant to be literal --
    // `**kwargs` in a code span must survive as typed.
    const spans = [];
    let out = escaped.replace(/`([^`\n]+)`/g, (m, body) => {
      spans.push(body);
      return "\u0000" + (spans.length - 1) + "\u0000";
    });

    out = out
      // Only http(s) and mailto become links. A `javascript:` href is the
      // one piece of markdown that is executable, and escaping does not
      // touch it because it is legal href text.
      .replace(
        /\[([^\]\n]+)\]\(((?:https?:\/\/|mailto:)[^\s)]+)\)/g,
        '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>'
      )
      .replace(/(\*\*|__)(?=\S)([\s\S]*?\S)\1/g, "<strong>$2</strong>")
      // Single-character emphasis needs a boundary either side, or
      // `some_var_name` and `@types/node` get chewed up mid-word.
      .replace(/(^|[\s(\[])([*_])(?=\S)([^*_\n]*?\S)\2(?=[\s).,;:!?\]]|$)/g, "$1<em>$3</em>")
      .replace(/~~(?=\S)([\s\S]*?\S)~~/g, "<del>$1</del>");

    return out.replace(/\u0000(\d+)\u0000/g, (m, i) => "<code>" + spans[i] + "</code>");
  }

  function renderMarkdown(source) {
    const lines = String(source == null ? "" : source).replace(/\r\n?/g, "\n").split("\n");
    const out = [];
    let para = [];
    let list = null;   // { tag: "ul" | "ol", items: [] }
    let fence = null;  // { body: [] }

    function flushPara() {
      if (!para.length) return;
      out.push("<p>" + inlineMd(esc(para.join("\n"))).replace(/\n/g, "<br>") + "</p>");
      para = [];
    }
    function flushList() {
      if (!list) return;
      const items = list.items
        .map((text) => "<li>" + inlineMd(esc(text)).replace(/\n/g, "<br>") + "</li>")
        .join("");
      out.push("<" + list.tag + ">" + items + "</" + list.tag + ">");
      list = null;
    }
    function flushAll() { flushPara(); flushList(); }
    function pushFence() {
      out.push("<pre><code>" + esc(fence.body.join("\n")) + "</code></pre>");
      fence = null;
    }

    for (const raw of lines) {
      if (fence) {
        if (/^\s*```/.test(raw)) pushFence();
        else fence.body.push(raw);
        continue;
      }
      if (/^\s*```/.test(raw)) { flushAll(); fence = { body: [] }; continue; }

      const line = raw.replace(/\s+$/, "");
      if (!line.trim()) { flushAll(); continue; }

      let m;
      if ((m = /^ {0,3}(#{1,6})\s+(.*)$/.exec(line))) {
        flushAll();
        const level = m[1].length;
        out.push("<h" + level + ">" + inlineMd(esc(m[2])) + "</h" + level + ">");
        continue;
      }
      if (/^ {0,3}([-*_])\s*\1\s*\1[\s\-*_]*$/.test(line)) {
        flushAll();
        out.push("<hr>");
        continue;
      }
      if ((m = /^ {0,3}>\s?(.*)$/.exec(line))) {
        flushAll();
        out.push("<blockquote>" + inlineMd(esc(m[1])) + "</blockquote>");
        continue;
      }
      if ((m = /^\s*[-*+]\s+(.*)$/.exec(line))) {
        flushPara();
        if (!list || list.tag !== "ul") { flushList(); list = { tag: "ul", items: [] }; }
        list.items.push(m[1]);
        continue;
      }
      if ((m = /^\s*\d{1,3}[.)]\s+(.*)$/.exec(line))) {
        flushPara();
        if (!list || list.tag !== "ol") { flushList(); list = { tag: "ol", items: [] }; }
        list.items.push(m[1]);
        continue;
      }
      // An indented line under a bullet continues it rather than starting a
      // paragraph that would render outside the list.
      if (list && !para.length && /^\s{2,}\S/.test(raw)) {
        list.items[list.items.length - 1] += "\n" + line.trim();
        continue;
      }
      flushList();
      para.push(line);
    }

    if (fence) pushFence();   // an answer cut off mid-fence still renders
    flushAll();
    return out.join("");
  }

  function build() {
    injectStyle();

    const launch = document.createElement("button");
    launch.className = "chatw-launch";
    launch.type = "button";
    launch.setAttribute("aria-label", "Ask the graph");
    launch.innerHTML = `<span class="gl">◈</span><span>Ask the graph</span>`;

    const panel = document.createElement("div");
    panel.className = "chatw-panel";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Ask the graph");
    panel.innerHTML = `
      <div class="chatw-head">
        <div>
          <div class="ttl">Ask the graph</div>
          <div class="sub">supply-chain Q&amp;A over this fleet</div>
        </div>
        <div class="spacer"></div>
        <button class="chatw-close" type="button" aria-label="Close">✕</button>
      </div>
      <div class="chatw-body"></div>
      <form class="chatw-form">
        <textarea class="chatw-input" rows="1" placeholder="Ask a question…"></textarea>
        <button class="chatw-send" type="submit">Ask</button>
      </form>
    `;

    document.body.append(launch, panel);

    const body = panel.querySelector(".chatw-body");
    const form = panel.querySelector(".chatw-form");
    const input = panel.querySelector(".chatw-input");
    const sendBtn = panel.querySelector(".chatw-send");
    const closeBtn = panel.querySelector(".chatw-close");

    let opened = false;
    let warmed = false;

    function addMsg(role, text) {
      const el = document.createElement("div");
      el.className = `chatw-msg ${role}`;
      el.textContent = text;
      body.append(el);
      body.scrollTop = body.scrollHeight;
      return el;
    }

    function showEmptyState() {
      const empty = document.createElement("div");
      empty.className = "chatw-empty";
      empty.textContent = "Ask about anything in the fleet's dependency graph -- what's exposed, what reaches production code, or what to patch first.";
      body.append(empty);

      fetch(`/api/chat/${workspaceRef()}/briefing`)
        .then((r) => (r.ok ? r.json() : Promise.reject(r)))
        .then((pack) => {
          const questions = (pack.suggestions || []).slice(0, 4);
          if (!questions.length) return;
          const wrap = document.createElement("div");
          wrap.className = "chatw-starters";
          for (const q of questions) {
            const btn = document.createElement("button");
            btn.className = "chatw-starter";
            btn.type = "button";
            btn.textContent = q;
            btn.onclick = () => ask(q);
            wrap.append(btn);
          }
          body.append(wrap);
        })
        .catch(() => {
          /* No key configured yet, or the graph is empty -- the first real
             question will surface the actual reason, so this stays quiet. */
        });
    }

    /* The stream is read with fetch + a ReadableStream reader rather than
       EventSource, for one reason: EventSource can only issue a GET, and the
       question is a POST body. So the SSE framing is reassembled here --
       frames split on a blank line, `data:` lines within a frame joined --
       which is all of the protocol this endpoint uses.

       `?stream=false` is still what the CLI and the tests call, and it stays
       the fallback below for any browser that hands back a response with no
       `body` to read. */
    async function readEvents(res, onEvent, onChunk) {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let cut;
        while ((cut = buffer.indexOf("\n\n")) !== -1) {
          const frame = buffer.slice(0, cut);
          buffer = buffer.slice(cut + 2);
          const payload = frame
            .split("\n")
            .filter((line) => line.startsWith("data:"))
            .map((line) => line.slice(5).replace(/^ /, ""))
            .join("\n");
          if (!payload) continue;
          try {
            onEvent(JSON.parse(payload));
          } catch (e) {
            /* A frame we cannot parse is a frame we cannot act on. Dropping
               it keeps the rest of the answer streaming, which is better
               than failing the whole reply over one bad line. */
          }
        }
        await onChunk();
      }
    }

    async function ask(message) {
      const trimmed = (message || "").trim();
      if (!trimmed) return;

      addMsg("user", trimmed);
      input.value = "";
      autosize();
      sendBtn.disabled = true;

      const bubble = addMsg("bot pending", "Thinking…");
      let answer = "";
      let dirty = false;
      let lastPaint = 0;

      // Re-rendering markdown per token is O(n^2) over the answer, so paints
      // are throttled to this. Deliberately NOT requestAnimationFrame: when a
      // burst of frames is already sitting in the socket buffer, every
      // `reader.read()` settles as a microtask, and microtasks drain to
      // completion before the browser's rendering step -- so the rAF callback
      // never runs until the stream ends and the whole answer lands in one
      // jump. See the yield in `flush` for the other half of that.
      const PAINT_MS = 60;

      function paint() {
        dirty = false;
        lastPaint = performance.now();
        const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 40;
        bubble.className = "chatw-msg bot md";
        bubble.innerHTML = renderMarkdown(answer);
        // Only chase the bottom if the reader is already there -- yanking the
        // scroll while somebody is reading back is worse than not following.
        if (atBottom) body.scrollTop = body.scrollHeight;
      }

      // Called once per network chunk rather than per token: paints if enough
      // time has passed, then hands the thread back through a macrotask so the
      // browser actually gets to render what was just written.
      async function flush() {
        if (!dirty || performance.now() - lastPaint < PAINT_MS) return;
        paint();
        await new Promise((resolve) => setTimeout(resolve, 0));
      }

      function fail(text) {
        dirty = false;
        bubble.className = "chatw-msg err";
        bubble.textContent = text;
        body.scrollTop = body.scrollHeight;
      }
      function notice(text) {
        const el = document.createElement("div");
        el.className = "chatw-flag";
        el.textContent = text;
        body.append(el);
        body.scrollTop = body.scrollHeight;
      }
      function flag(specs) {
        notice(
          "Heads up: this answer named " + specs.join(", ") +
          ", which this repository does not resolve. Treat it as unverified."
        );
      }

      let status = null;
      function tool(name) {
        if (answer) return;  // tokens have started; the status line is stale
        if (!status) {
          status = document.createElement("div");
          status.className = "chatw-tool";
          body.insertBefore(status, bubble);
        }
        status.textContent = "checking " + name + "…";
        body.scrollTop = body.scrollHeight;
      }

      function handle(event) {
        switch (event.type) {
          case "token":
            answer += event.text || "";
            if (status) { status.remove(); status = null; }
            dirty = true;
            break;
          case "tool":
            tool(event.name || "the graph");
            break;
          case "ungrounded":
            if ((event.specs || []).length) flag(event.specs);
            break;
          case "error":
            fail(event.message || "The chat agent failed mid-answer.");
            break;
          default:
            /* start / refused / done carry no text of their own. The refusal
               body arrives as ordinary tokens, so it renders like any other
               answer. */
            break;
        }
      }

      try {
        const res = await fetch(`/api/chat/${workspaceRef()}/ask`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "text/event-stream",
          },
          body: JSON.stringify({ message: trimmed, session_id: sessionId() }),
        });

        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          fail(data.detail || `The chat agent answered with an error (${res.status}).`);
        } else if (!res.body) {
          const data = await askWhole(trimmed);
          if (data.error) fail(data.error);
          else { answer = data.answer || ""; paint(); }
        } else {
          await readEvents(res, handle, flush);
          if (!answer && bubble.classList.contains("pending")) {
            fail("The chat agent closed the stream without answering.");
          } else if (answer) {
            paint();
          }
        }
      } catch (e) {
        if (answer) {
          // Partial answers are kept: the stream dropped, but what already
          // arrived came from the graph and is still true. Said out loud,
          // because a reply that stops mid-sentence otherwise reads as the
          // whole answer.
          paint();
          notice("The connection dropped before this answer finished.");
        } else {
          fail("Could not reach the chat agent. Is the server running?");
        }
      } finally {
        if (status) { status.remove(); status = null; }
        sendBtn.disabled = false;
      }
    }

    /* The non-streaming route, kept for a browser that gives us no readable
       body. Same endpoint, same shape the CLI and the tests use. */
    async function askWhole(message) {
      const res = await fetch(`/api/chat/${workspaceRef()}/ask?stream=false`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, session_id: sessionId() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { error: data.detail || `The chat agent answered with an error (${res.status}).` };
      }
      return data;
    }

    function autosize() {
      input.style.height = "auto";
      input.style.height = Math.min(input.scrollHeight, 84) + "px";
    }
    input.addEventListener("input", autosize);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        form.requestSubmit();
      }
    });

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      ask(input.value);
    });

    function open() {
      opened = true;
      launch.classList.add("open");
      panel.classList.add("open");
      if (!body.children.length) showEmptyState();
      if (!warmed) {
        warmed = true;
        fetch(`/api/chat/${workspaceRef()}/warm`, { method: "POST" }).catch(() => {});
      }
      input.focus();
    }

    function close() {
      opened = false;
      launch.classList.remove("open");
      panel.classList.remove("open");
      launch.focus();
    }

    launch.addEventListener("click", open);
    closeBtn.addEventListener("click", close);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && opened) close();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", build);
  } else {
    build();
  }
})();
