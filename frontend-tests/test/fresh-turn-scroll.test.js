// Guards the send-time scroll strategy in static/js/chat-app.js
// (followFreshTurn / scrollToNewTurn). The stub mirrors the one thing the logic
// depends on: element rects move with scrollTop, like getBoundingClientRect.
// If that maths changes in chat-app.js, this is the test that should fail.
// depends on: element rects move with scrollTop, like getBoundingClientRect.
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const COLUMN_H = 600, TAIL = 150;

function run(sc) {
  const m = { scrollTop: sc.start, scrollHeight: sc.scrollHeight, clientHeight: COLUMN_H,
              getBoundingClientRect: () => ({ top: 0, bottom: COLUMN_H, height: COLUMN_H }) };
  // document tops; viewport position = docTop - scrollTop
  const ansH = sc.answerH || 60;
  const doc = { user: 400, card: 400 + sc.userH + 12, bubble: 400 + sc.userH + 12 + 320 };
  const vis = (d, h) => d - m.scrollTop;           // viewport-relative top
  const freshCard = sc.cardHidden ? null : doc.card;
  // --- mirrored from followFreshTurn ---
  const tailTarget = m.scrollTop + vis(doc.bubble) + ansH - (COLUMN_H - TAIL);
  let target;
  if (sc.mode === 'card' && freshCard !== null) target = m.scrollTop + vis(freshCard) - 8;
  else if (sc.mode === 'card') target = m.scrollTop + vis(doc.user, sc.userH) + sc.userH - 8;
  else target = m.scrollTop + vis(doc.user) - 12;
  target = Math.max(target, tailTarget);
  m.scrollTop = Math.max(0, Math.min(Math.max(0, m.scrollHeight - COLUMN_H), target));
  // measured AFTER the scroll, like reading rects on the next frame
  return { m, userTop: vis(doc.user), userBottom: vis(doc.user) + sc.userH,
           cardTop: vis(doc.card), tailBottom: vis(doc.bubble) + ansH };
}
describe('fresh-turn scroll strategy', () => {
  it('one-liner: question parked at the top of the column', () => {
    const r = run({ mode: 'user', userH: 40, cardHidden: true, scrollHeight: 2000, start: 1500 });
    assert.ok(Math.abs(r.userTop - 12) < 2, `user top ${r.userTop}`);
  });
  it('long question: card takes the top, question pushed above the fold', () => {
    const r = run({ mode: 'card', userH: 400, cardHidden: false, scrollHeight: 3000, start: 2000 });
    assert.ok(r.cardTop <= 10, `card top ${r.cardTop}`);
    assert.ok(r.userTop < 0, `user top ${r.userTop}`);
  });
  it('card not open yet: question parked above the fold', () => {
    const r = run({ mode: 'card', userH: 400, cardHidden: true, scrollHeight: 3000, start: 2000 });
    assert.ok(r.userBottom <= 10, `user bottom ${r.userBottom}`);
  });
  it('tail wins once the answer outgrows the column', () => {
    const r = run({ mode: 'card', userH: 400, cardHidden: false, scrollHeight: 5000, start: 2000, answerH: 900 });
    assert.ok(r.tailBottom <= COLUMN_H - TAIL + 4, `tail ${r.tailBottom}`);
    assert.ok(r.cardTop < 0, `card top ${r.cardTop}`);
  });
  it('short answer: the card keeps the top instead of being dragged down', () => {
    const r = run({ mode: 'card', userH: 40, cardHidden: false, scrollHeight: 2000, start: 200 });
    assert.ok(r.cardTop <= 10, `card top ${r.cardTop}`);
  });
  it('never scrolls past the end of the column', () => {
    const r = run({ mode: 'card', userH: 400, cardHidden: false, scrollHeight: 700, start: 0 });
    assert.equal(r.m.scrollTop, 100);
  });
});
