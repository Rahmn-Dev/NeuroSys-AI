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
 window:{sreAgentWs:{readyState:1, send(x){ctx.sent.push(JSON.parse(x));}},setRunPhase(){},setSendButtonState(state){ctx.sendBtn.disabled=state==='running';},refreshInvestigations(){},markRunFinished(){},closeTurn(){},paintBlockedBubble(){},quarantineUserBubble(){}},WebSocket:{OPEN:1},
 sent:[],steps:[],sessionId:'',stepTimers:{running:{}},stopStep(id){delete ctx.stepTimers[id];},
 stopAllAgentStepTimers(){ctx.stepTimers={};},
 updateRunStateCard(){},finalizeRunWrap(){},addAIMessage(){return {};},
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
const submitStart = html.indexOf("form.addEventListener('submit'");
const submitEnd = html.indexOf('// Auto-resize textarea', submitStart);
const submitHandler = html.slice(submitStart, submitEnd);
assert.match(submitHandler, /window\.openTurn\(\)/);
assert.match(submitHandler, /window\.openTurn\(\)[\s\S]*startRunWrap\(\)/);
passed++;
const directStart = html.indexOf("case 'direct_chat':");
const directEnd = html.indexOf("case 'exploring':", directStart);
const directHandler = html.slice(directStart, directEnd);
assert.doesNotMatch(directHandler, /startRunWrap\(|ensureRunWrap\(|paintRunWrap\(/);
assert.doesNotMatch(directHandler, /closeTurn\(\)/);
const exploringEnd = html.indexOf("case 'discovering_tools':", directEnd);
assert.match(html.slice(directEnd, exploringEnd), /startRunWrap\(\)|addAgentStep\(/);
const completedStart = html.indexOf("case 'completed':", directEnd);
const completedEnd = html.indexOf("case 'error':", completedStart);
const completedHandler = html.slice(completedStart, completedEnd);
assert.match(completedHandler, /completedRunId = data\.run_id \|\| \(directTurn \? currentDirectRunId/);
assert.match(completedHandler, /updateRunStateCard\(completedRunId, 'completed'/);
assert.match(completedHandler, /attachRunAudit/);
const thinkingStart = html.indexOf("case 'thinking':", directEnd);
const thinkingEnd = html.indexOf("case 'hypothesis':", thinkingStart);
assert.match(html.slice(thinkingStart, thinkingEnd), /currentTurnWasDirect\) updateRunStateCard\(currentDirectRunId, 'thinking'\)/);
passed += 5;
console.log(JSON.stringify({passed,failed:0,scope:'actual template handlers; deterministic DOM stubs, not browser screenshots'}));
