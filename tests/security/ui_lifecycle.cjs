const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync('ai_config/templates/chat3.html','utf8');
function extract(name) {
 const start=html.indexOf('    function '+name+'(');
 const end=html.indexOf('\n    }',start)+6;
 return html.slice(start,end);
}
const elements={};
const ctx={document:{getElementById(id){return elements[id] ||= {style:{},hidden:true,disabled:false};}},
 window:{sreAgentWs:{readyState:1, send(x){ctx.sent.push(JSON.parse(x));}}},WebSocket:{OPEN:1},
 sent:[],steps:[],stepTimers:{running:{}},stopStep(id){delete ctx.stepTimers[id];},
 setInterval(){return 1;},clearInterval(){},Date,Number,JSON,Math,
 addAgentStep(...x){ctx.steps.push(x);},addSystemMsg(){},scrollToBottom(){},escapeHtml:x=>x,
 isProcessing:true,sendBtn:{disabled:true,style:{}},pendingApproval:null,approvalTimer:null,
 activeInvestigationId:null};
vm.createContext(ctx);
vm.runInContext(['hideApprovalCard','showApprovalCard','handleEvent'].map(extract).join('\n'),ctx);
let passed=0;
ctx.handleEvent({type:'approval_required'});
assert.equal(elements['approval-card'],undefined); passed++;
ctx.handleEvent({type:'approval_required',approval_id:4,session_id:'s',expires_at:new Date(Date.now()+30000).toISOString(),args:{target:'redacted'}});
assert.equal(elements['approval-card'].hidden,false);
assert.equal(ctx.isProcessing,true);assert.equal(ctx.sendBtn.disabled,true);
assert.equal(Object.keys(ctx.stepTimers).length,0);passed++;
elements['approval-allow'].onclick();assert.equal(ctx.sent[0].type,'approval');assert.equal(ctx.sent[0].approved,true);passed++;
ctx.handleEvent({type:'approval_approved'});assert.equal(elements['approval-card'].hidden,true);assert.equal(ctx.sent.length,1);passed++;
for(const type of ['denied','denied_timeout','security_blocked']) {
 ctx.isProcessing=true;ctx.stepTimers={running:{}};
 ctx.handleEvent({type,content:type});
 assert.equal(ctx.isProcessing,false);assert.equal(ctx.sendBtn.disabled,false);
 assert.equal(Object.keys(ctx.stepTimers).length,0);passed++;
}
assert.match(html, /if \(!isProcessing\) await loadSession\(sessionId\);/);
passed++;
assert.match(html, /workerTerminal[\s\S]*fa-circle-check/);
passed++;
console.log(JSON.stringify({passed,failed:0,scope:'actual template handlers; deterministic DOM stubs, not browser screenshots'}));
