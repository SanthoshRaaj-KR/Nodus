/* =====================================================================
   The "ask the graph" popup: one floating button, bottom-right, on every
   page. Talks to /api/chat/default -- the one workspace the chat router
   auto-provisions over every service currently in the graph (there is no
   per-repo picker here; these three pages already treat the graph as one
   fleet, so the popup does too).

   Self-contained on purpose, like chrome.js: one file, injected on every
   page, owning its own markup and styles so the page templates stay free
   of anything chat-specific.
   ===================================================================== */
"use strict";

(function () {
  const STYLE_ID = "chatw-style";
  const SESSION_KEY = "blastradius.chat.session";

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

      fetch("/api/chat/default/briefing")
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

    async function ask(message) {
      const trimmed = (message || "").trim();
      if (!trimmed) return;

      addMsg("user", trimmed);
      input.value = "";
      autosize();
      sendBtn.disabled = true;

      const pending = addMsg("bot pending", "Thinking…");

      try {
        const res = await fetch("/api/chat/default/ask?stream=false", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: trimmed, session_id: sessionId() }),
        });
        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
          pending.className = "chatw-msg err";
          pending.textContent = data.detail || `The chat agent answered with an error (${res.status}).`;
        } else if (data.error) {
          pending.className = "chatw-msg err";
          pending.textContent = data.error;
        } else {
          pending.className = "chatw-msg bot";
          pending.textContent = data.answer || "(no answer)";
        }
      } catch (e) {
        pending.className = "chatw-msg err";
        pending.textContent = "Could not reach the chat agent. Is the server running?";
      } finally {
        sendBtn.disabled = false;
        body.scrollTop = body.scrollHeight;
      }
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
        fetch("/api/chat/default/warm", { method: "POST" }).catch(() => {});
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
