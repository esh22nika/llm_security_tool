import re

html_file = r"templates\\index.html"
with open(html_file, "r", encoding="utf-8") as f:
    html = f.read()

new_style = """<style>
  :root {
    --bg: #f8fafc;
    --bg2: #ffffff;
    --bg3: #f1f5f9;
    --border: #e2e8f0;
    --text: #1e293b;
    --muted: #64748b;
    --accent: #0f5132;       /* Dark green primary */
    --accent2: #1e3a8a;      /* Dark blue secondary */
    --red: #dc2626;
    --green: #166534;
    --amber: #b45309;
    --cyan: #0369a1;
    --pink: #be185d;
    --card-r: 12px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; font-size: 15px; line-height: 1.7; height: 100vh; overflow: hidden; display: flex; flex-direction: column; }

  /* ── TOPBAR ── */
  .topbar { display: flex; align-items: center; gap: 16px; padding: 16px 24px; background: var(--bg2); border-bottom: 1px solid var(--border); flex-shrink: 0; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }
  .logo { font-size: 20px; font-weight: 800; color: var(--accent2); letter-spacing: -0.5px; }
  .logo span { color: var(--accent); }
  .tagline { color: var(--muted); font-size: 13px; font-weight: 500; }
  .spacer { flex: 1; }

  /* Mode toggle */
  .mode-wrap { display: flex; align-items: center; gap: 10px; }
  .mode-label { font-size: 13px; color: var(--muted); font-weight: 600; }
  .toggle-outer { position: relative; width: 56px; height: 30px; background: var(--border); border: 2px solid transparent; border-radius: 15px; cursor: pointer; transition: background .3s; }
  .toggle-outer.on { background: var(--accent); }
  .toggle-knob { position: absolute; top: 2px; left: 2px; width: 22px; height: 22px; border-radius: 50%; background: #fff; transition: transform .3s, background .3s; box-shadow: 0 1px 2px rgba(0,0,0,0.1); }
  .toggle-outer.on .toggle-knob { transform: translateX(26px); background: #ffffff; }
  .mode-badge { padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: .5px; margin-left: 4px; }
  .mode-badge.unprotected { background: #fee2e2; color: var(--red); border: 1px solid #fca5a5; }
  .mode-badge.protected { background: #dcfce7; color: var(--accent); border: 1px solid #86efac; }

  /* ── LAYOUT ── */
  .layout { display: grid; grid-template-columns: 280px 1fr 340px; flex: 1; overflow: hidden; }

  /* ── LEFT SIDEBAR — Attack Playbook ── */
  .sidebar-left { background: var(--bg2); border-right: 1px solid var(--border); overflow-y: auto; display: flex; flex-direction: column; }
  .sidebar-title { padding: 16px 20px; font-size: 12px; font-weight: 800; color: var(--accent2); text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid var(--border); background: var(--bg3); }
  .attack-group { padding: 12px 0; border-bottom: 1px solid var(--border); }
  .attack-group-name { padding: 8px 20px; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .8px; }
  .attack-group-name.lm01 { color: var(--red); }
  .attack-group-name.lm04 { color: var(--amber); }
  .attack-group-name.lm03 { color: var(--cyan); }
  .attack-btn { display: flex; flex-direction: column; width: 100%; text-align: left; padding: 10px 20px; background: none; border: none; cursor: pointer; color: var(--text); transition: background .15s; gap: 4px; }
  .attack-btn:hover { background: var(--bg3); }
  .attack-btn .atk-name { font-size: 13px; font-weight: 600; color: var(--accent2); }
  .attack-btn .atk-desc { font-size: 11px; color: var(--muted); line-height: 1.4; }
  .attack-btn .atk-tag { font-size: 10px; padding: 2px 6px; border-radius: 4px; width: fit-content; margin-top: 4px; font-weight: 600; }
  .tag-critical { background: #fee2e2; color: var(--red); }
  .tag-high { background: #fef3c7; color: var(--amber); }
  .tag-medium { background: #e0e7ff; color: var(--accent2); }

  /* ── CENTER — Chat ── */
  .chat-area { display: flex; flex-direction: column; overflow: hidden; background: var(--bg); }
  .chat-messages { flex: 1; overflow-y: auto; padding: 24px; display: flex; flex-direction: column; gap: 20px; }
  .msg { display: flex; gap: 14px; max-width: 100%; }
  .msg.user { flex-direction: row-reverse; }
  .msg-avatar { width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 16px; flex-shrink: 0; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
  .msg.user .msg-avatar { background: var(--accent); color: #fff; }
  .msg.bot .msg-avatar { background: #fff; border: 1px solid var(--border); color: var(--accent2); }
  .msg-bubble { max-width: calc(100% - 100px); padding: 14px 18px; border-radius: 16px; font-size: 14px; line-height: 1.7; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
  .msg.user .msg-bubble { background: var(--accent); color: #fff; border-bottom-right-radius: 4px; }
  .msg.bot .msg-bubble { background: var(--bg2); border: 1px solid var(--border); border-bottom-left-radius: 4px; }
  .msg-bubble strong { font-weight: 700; color: inherit; }
  .msg.bot .msg-bubble strong { color: var(--accent2); }
  .msg-bubble hr { border: none; border-top: 1px solid var(--border); margin: 12px 0; }

  /* Attack result badges */
  .attack-success { background: #fee2e2; border: 1px solid #fca5a5; border-radius: 8px; padding: 12px; margin-bottom: 12px; font-size: 13px; color: var(--red); }
  .attack-blocked { background: #dcfce7; border: 1px solid #86efac; border-radius: 8px; padding: 12px; margin-bottom: 12px; font-size: 13px; color: var(--accent); }
  .block-detail { margin-top: 6px; color: var(--muted); font-size: 12px; line-height: 1.5; }

  /* Chat input */
  .chat-input-wrap { padding: 16px 24px; border-top: 1px solid var(--border); background: var(--bg2); display: flex; gap: 12px; align-items: flex-end; }
  .chat-input { flex: 1; background: var(--bg3); border: 1px solid var(--border); border-radius: 12px; padding: 12px 16px; color: var(--text); font-size: 14px; resize: none; min-height: 48px; max-height: 150px; font-family: inherit; transition: border-color .2s; }
  .chat-input:focus { outline: none; border-color: var(--accent); background: #fff; box-shadow: 0 0 0 3px rgba(15, 81, 50, 0.1); }
  .send-btn { background: var(--accent); color: #fff; border: none; border-radius: 12px; padding: 10px 24px; font-size: 14px; font-weight: 700; cursor: pointer; height: 48px; transition: all .2s; }
  .send-btn:hover { background: #0b3d26; transform: translateY(-1px); }
  .send-btn:disabled { opacity: .6; cursor: not-allowed; transform: none; }

  /* Tabs */
  .tab-bar { display: flex; gap: 0; border-bottom: 1px solid var(--border); background: var(--bg2); flex-shrink: 0; }
  .tab { padding: 14px 20px; font-size: 13px; font-weight: 600; cursor: pointer; color: var(--muted); border: none; border-bottom: 3px solid transparent; transition: all .2s; background: none; }
  .tab.active { color: var(--accent2); border-bottom-color: var(--accent2); }
  .tab:hover:not(.active) { color: var(--text); background: var(--bg3); }

  /* ── RIGHT PANEL ── */
  .sidebar-right { background: var(--bg2); border-left: 1px solid var(--border); overflow-y: auto; display: flex; flex-direction: column; }
  .panel-section { padding: 20px; border-bottom: 1px solid var(--border); }
  .panel-section-title { font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; color: var(--accent2); margin-bottom: 14px; }

  /* Pipeline trace */
  .trace-step { display: flex; flex-direction: column; gap: 6px; padding: 12px; border-radius: 8px; margin-bottom: 10px; background: var(--bg3); border: 1px solid var(--border); }
  .trace-header { display: flex; align-items: center; gap: 8px; }
  .trace-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .trace-dot.NONE, .trace-dot.LOW { background: var(--green); }
  .trace-dot.MEDIUM { background: var(--amber); }
  .trace-dot.HIGH, .trace-dot.CRITICAL { background: var(--red); }
  .trace-name { font-size: 12px; font-weight: 700; flex: 1; color: var(--text); }
  .trace-badge { font-size: 10px; padding: 2px 8px; border-radius: 12px; font-weight: 700; }
  .badge-pass { background: #dcfce7; color: var(--green); }
  .badge-block { background: #fee2e2; color: var(--red); }
  .badge-warn { background: #fef3c7; color: var(--amber); }
  .trace-detail { font-size: 11px; color: var(--muted); line-height: 1.5; }
  .trace-bar-wrap { height: 4px; background: var(--border); border-radius: 2px; margin-top: 6px; }
  .trace-bar { height: 4px; border-radius: 2px; background: var(--green); transition: width .5s; }
  .trace-matched { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
  .match-pill { font-size: 10px; padding: 2px 8px; background: #fee2e2; color: #b91c1c; border-radius: 4px; }

  /* Stats */
  .scoreboard { display: flex; gap: 16px; }
  .score-col { flex: 1; text-align: center; padding: 16px; background: var(--bg); border-radius: 10px; border: 1px solid var(--border); }
  .score-num { font-size: 32px; font-weight: 800; }
  .score-num.exploit { color: var(--red); }
  .score-num.blocked { color: var(--accent); }
  .score-subtitle { font-size: 11px; font-weight: 600; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }

  /* Confidence meter */
  .confidence-wrap { margin-top: 8px; }
  .confidence-label { display: flex; justify-content: space-between; font-size: 12px; font-weight: 600; color: var(--muted); margin-bottom: 6px; }
  .confidence-bar { height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; }
  .confidence-fill { height: 8px; border-radius: 4px; background: var(--green); transition: width .5s, background .5s; }

  /* Prompt diff */
  .diff-wrap { font-size: 12px; font-family: 'Courier New', monospace; }
  .diff-label { font-size: 11px; font-weight: 600; color: var(--muted); margin-bottom: 6px; font-family: 'Inter', sans-serif; }
  .diff-raw { background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 10px; color: #991b1b; margin-bottom: 12px; word-break: break-all; }
  .diff-safe { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 10px; color: #166534; word-break: break-all; }

  /* RAG records */
  .rag-record { font-size: 12px; padding: 10px 14px; background: var(--bg3); border-radius: 8px; margin-bottom: 8px; border-left: 4px solid var(--border); }
  .rag-record.poisoned { border-left-color: var(--red); background: #fef2f2; }
  .rag-record.clean { border-left-color: var(--green); }
  .rag-title { font-weight: 700; color: var(--accent2); margin-bottom: 4px; }
  .rag-source { color: var(--muted); font-size: 11px; }

  /* Poison Lab */
  .poison-lab { padding: 24px; overflow-y: auto; }
  .poison-lab h3 { font-size: 16px; font-weight: 800; color: var(--amber); margin-bottom: 12px; }
  .poison-lab p { font-size: 13px; color: var(--muted); margin-bottom: 20px; line-height: 1.6; }
  .form-group { margin-bottom: 16px; }
  .form-label { font-size: 12px; font-weight: 600; color: var(--text); margin-bottom: 6px; display: block; }
  .form-input { width: 100%; background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; color: var(--text); font-size: 13px; font-family: inherit; }
  .form-input:focus { outline: none; border-color: var(--amber); box-shadow: 0 0 0 3px rgba(180, 83, 9, 0.1); }
  .form-select { width: 100%; background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; color: var(--text); font-size: 13px; border-right: 14px solid #fff; }
  .form-textarea { min-height: 100px; resize: vertical; }
  .inject-btn { width: 100%; background: var(--amber); color: #fff; border: none; border-radius: 8px; padding: 12px; font-size: 14px; font-weight: 700; cursor: pointer; transition: background .2s; }
  .inject-btn:hover { background: #92400e; }
  .reset-btn { width: 100%; background: #fff; color: var(--red); border: 1px solid var(--red); border-radius: 8px; padding: 12px; font-size: 14px; font-weight: 700; cursor: pointer; margin-top: 10px; transition: all .2s; }
  .reset-btn:hover { background: #fef2f2; }
  .inject-result { margin-top: 16px; font-size: 12px; padding: 12px; border-radius: 8px; line-height: 1.5; }
  .inject-result.success { background: #fffbeb; border: 1px solid #fde68a; color: #92400e; }
  .inject-result.detected { background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }
  .injected-count { background: #fef3c7; color: var(--amber); border-radius: 12px; padding: 2px 8px; font-size: 11px; font-weight: 800; display: inline-block; margin-left: 6px; }

  /* Model probe */
  .model-probe { padding: 24px; }
  .model-probe h3 { font-size: 16px; font-weight: 800; color: var(--cyan); margin-bottom: 12px; }
  .model-row { display: flex; gap: 10px; margin-bottom: 16px; }
  .model-input { flex: 1; background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; color: var(--text); font-size: 13px; }
  .probe-btn { background: var(--cyan); color: #fff; border: none; border-radius: 8px; padding: 10px 20px; font-size: 13px; font-weight: 700; cursor: pointer; white-space: nowrap; transition: background .2s; }
  .probe-btn:hover { background: #026acc; }
  .model-presets { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
  .preset-btn { font-size: 11px; font-weight: 600; padding: 6px 12px; background: #fff; border: 1px solid var(--border); border-radius: 6px; cursor: pointer; color: var(--muted); transition: all .15s; }
  .preset-btn:hover { color: var(--accent2); border-color: var(--accent2); background: var(--bg3); }
  .probe-result { font-size: 12px; background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-top: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
  .probe-result .pr-row { display: flex; justify-content: space-between; margin-bottom: 8px; }
  .pr-key { color: var(--muted); font-weight: 600; }
  .flag-item { color: var(--amber); font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--border); }
  .flag-item:last-child { border-bottom: none; }

  /* Heatmap */
  .heatmap-wrap { display: flex; flex-direction: column; gap: 10px; }
  .heat-row { display: flex; align-items: center; gap: 12px; }
  .heat-label { font-size: 11px; font-weight: 600; color: var(--muted); width: 140px; flex-shrink: 0; text-transform: capitalize; }
  .heat-bar-outer { flex: 1; height: 16px; background: var(--border); border-radius: 8px; overflow: hidden; }
  .heat-bar-inner { height: 16px; background: var(--red); border-radius: 8px; transition: width .5s; min-width: 0; }
  .heat-count { font-size: 11px; font-weight: 700; color: var(--text); width: 24px; text-align: right; }

  /* Loading spinner */
  .spinner { width: 18px; height: 18px; border: 2px solid var(--border); border-top-color: var(--accent2); border-radius: 50%; animation: spin .6s linear infinite; display: inline-block; vertical-align: middle; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 8px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }

  /* Toast */
  .toast { position: fixed; bottom: 24px; right: 24px; background: var(--text); color: #fff; border-radius: 8px; padding: 14px 20px; font-size: 13px; font-weight: 500; box-shadow: 0 4px 6px rgba(0,0,0,0.1); z-index: 1000; transition: all .3s cubic-bezier(0.4, 0, 0.2, 1); max-width: 320px; display: flex; align-items: center; gap: 12px; }
  .toast.hide { opacity: 0; transform: translateY(20px); pointer-events: none; }

  /* Logs tab */
  .logs-panel { padding: 24px; font-family: 'Courier New', monospace; background: var(--text); color: #e2e8f0; min-height: 100%; }
  .log-entry { font-size: 12px; padding: 6px 0; border-bottom: 1px solid #334155; }
  .log-entry.BLOCK { color: #fca5a5; }
  .log-entry.WARN { color: #fde047; }
  .log-entry.PASS { color: #86efac; }
  .log-entry.ERROR { color: #f472b6; }

  .empty-state { color: var(--muted); font-size: 13px; text-align: center; padding: 30px; border: 1px dashed var(--border); border-radius: 8px; background: var(--bg); }
</style>"""

new_html = re.sub(r'<style>.*?</style>', new_style, html, flags=re.DOTALL)

with open(html_file, "w", encoding="utf-8") as f:
    f.write(new_html)

print("CSS updated successfully.")
