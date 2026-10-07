const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync('ai_config/templates/chat3.html','utf8');
const api = fs.readFileSync('ai_config/chatbot/api.py','utf8');
const engine = fs.readFileSync('ai_config/sre_agent/engine.py','utf8');
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
assert.match(html, /allWorkersSucceeded[\s\S]*Workers Finished/);
assert.match(html, /last_tool_status[\s\S]*last_tool_result/);
assert.match(html, /function updateInvestigationWorkerActivity[\s\S]*workflow\.push/);
assert.match(html, /workerWorkflowHtml[\s\S]*Worker workflow/);
assert.match(engine, /guided workers were blocked[\s\S]*One or more guided workers failed/);
passed++;
assert.match(html, /const allInvKeys = Object\.keys\(investigations\)\.sort/);
assert.match(html, /return createdAt\(b\) - createdAt\(a\)/);
assert.match(html, /createdAt: inv\.created_at \|\| inv\.createdAt \|\| 0/);
assert.match(html, /window\.setInvestigationFilter = function/);
assert.match(html, /aria-label="Filter investigations"/);
assert.match(html, /sre-inv-date/);
assert.match(api, /order_by\('-created_at', '-id'\)/);
passed++;
const submitStart = html.indexOf("form.addEventListener('submit'");
const submitEnd = html.indexOf('// Auto-resize textarea', submitStart);
const submitHandler = html.slice(submitStart, submitEnd);
assert.match(submitHandler, /window\.openTurn\(\)/);
assert.match(submitHandler, /window\.openTurn\(\)[\s\S]*startRunWrap\(\)/);
assert.match(submitHandler, /window\.scrollToNewTurn\(\)/);
assert.match(html, /window\.scrollToNewTurn = function \(\)[\s\S]*requestAnimationFrame\(\(\) => requestAnimationFrame\(follow\)\)/);
passed++;
const scrollHelperStart = html.indexOf('function scrollToBottom(force)');
const scrollHelperEnd = html.indexOf('// A new turn inserts its user bubble', scrollHelperStart);
const scrollHelpers = html.slice(scrollHelperStart, scrollHelperEnd);
assert.match(scrollHelpers, /if \(!force && window\.runHeaderPinned\) return/);
assert.match(scrollHelpers, /window\.centerRunTurn = function[\s\S]*groupCenter[\s\S]*viewCenter/);
assert.match(html, /messagesDiv\.addEventListener\('scroll',[\s\S]*window\.agentAutoScroll = false/);
const finalizeStart = html.indexOf('function finalizeRunWrap(');
const finalizeEnd = html.indexOf('// History replay grouping', finalizeStart);
assert.match(html.slice(finalizeStart, finalizeEnd), /toggleRunWrap\(wrapId, false\)/);
assert.match(html.slice(finalizeStart, finalizeEnd), /window\.centerRunTurn\(wrapId\)/);
assert.match(html, /if \(!window\.isLoadingHistory && window\.runHeaderPinned && window\.activeRunWrap[\s\S]*window\.centerRunTurn/);
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
