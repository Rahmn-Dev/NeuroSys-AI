// Smoke tests for the pure helpers in ai_config/static/js/chat-utils.js.
// The bundle is a classic script, so it is executed inside a jsdom window
// exactly like the browser would - no imports, no bundler, no mocks except
// the DOM itself.
const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const UTILS_SRC = fs.readFileSync(
  path.join(__dirname, '..', '..', 'ai_config', 'static', 'js', 'chat-utils.js'),
  'utf8'
);

function bootDom(html) {
  const dom = new JSDOM(
    `<!DOCTYPE html><html><head></head><body>${html || ''}</body></html>`,
    { url: 'http://localhost/chat3/', runScripts: 'dangerously' }
  );
  const script = dom.window.document.createElement('script');
  script.textContent = UTILS_SRC;
  dom.window.document.body.appendChild(script);
  return dom.window;
}

describe('escapeHtml', () => {
  let window;
  before(() => { window = bootDom(); });

  it('encodes angle brackets so markup cannot execute', () => {
    assert.equal(window.escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('encodes ampersands but leaves quotes as-is (text-node serialisation)', () => {
    // innerHTML serialisation of a text node only escapes & < > - quotes are
    // safe inside element text, and the chat renders answers as text nodes.
    assert.equal(window.escapeHtml('a"b&c\'d'), 'a"b&amp;c\'d');
  });

  it('leaves plain text untouched', () => {
    assert.equal(window.escapeHtml('hello world 123'), 'hello world 123');
  });
});

describe('chatTimeLabel', () => {
  let window;
  before(() => { window = bootDom(); });

  it('formats an ISO timestamp as HH:MM', () => {
    const label = window.chatTimeLabel('2026-10-10T11:29:00+07:00');
    assert.match(label, /^\d{2}[.:]\d{2}$/);
  });

  it('returns empty string for garbage input', () => {
    assert.equal(window.chatTimeLabel('not-a-date'), '');
  });

  it('defaults to now when called without arguments', () => {
    assert.match(window.chatTimeLabel(), /^\d{2}[.:]\d{2}$/);
  });
});

describe('turnRailEntry', () => {
  it('extracts question, answer excerpt and time from a turn', () => {
    const window = bootDom(`
      <div id="chat-messages">
        <div class="sre-msg-user" data-created="2026-10-10T11:29:00+07:00">who are u</div>
        <div class="sre-run-card" id="runwrap-abc"></div>
        <div class="agent-msg sre-msg-ai">
          <div class="ai-content">I am NeuroSysAI, ready to help with SRE work.</div>
        </div>
      </div>`);
    const userEl = window.document.querySelector('.sre-msg-user');
    const entry = window.turnRailEntry(userEl);
    assert.equal(entry.q, 'who are u');
    assert.ok(entry.a.startsWith('I am NeuroSysAI'));
    assert.match(entry.t, /^\d{2}[.:]\d{2}$/);
    assert.equal(entry.el, userEl);
  });

  it('strips the attachment footer from the question', () => {
    const window = bootDom(`
      <div class="sre-msg-user">check this\n\n[Context Attached: file:///tmp/a.log]</div>
      <div class="agent-msg sre-msg-ai"><div class="ai-content">ok</div></div>`);
    const entry = window.turnRailEntry(window.document.querySelector('.sre-msg-user'));
    assert.equal(entry.q, 'check this');
  });

  it('skips non-answer siblings when looking for the reply', () => {
    const window = bootDom(`
      <div class="sre-msg-user">hi</div>
      <div class="sre-run-card"></div>
      <div style="font-size:10px">11:29</div>
      <div class="agent-msg sre-msg-ai"><div class="ai-content">hello</div></div>`);
    const entry = window.turnRailEntry(window.document.querySelector('.sre-msg-user'));
    assert.equal(entry.a, 'hello');
  });

  it('reports an empty answer while the run is still working', () => {
    const window = bootDom(`<div class="sre-msg-user">long task</div><div class="sre-run-card"></div>`);
    const entry = window.turnRailEntry(window.document.querySelector('.sre-msg-user'));
    assert.equal(entry.a, '');
    assert.equal(entry.q, 'long task');
  });

  it('falls back for an empty question bubble', () => {
    const window = bootDom(`<div class="sre-msg-user">   </div>`);
    const entry = window.turnRailEntry(window.document.querySelector('.sre-msg-user'));
    assert.equal(entry.q, '(empty question)');
  });
});
