const fs = require('node:fs');
const vm = require('node:vm');
let count = 0;
for (const file of ['chat3.html', 'layout/layout1.html', 'network_security.html']) {
  const html = fs.readFileSync(`ai_config/templates/${file}`, 'utf8');
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (/\bsrc=|application\/json/.test(match[1]) || !match[2].trim()) continue;
    const source = match[2].replace(/{%[\s\S]*?%}/g, '').replace(/{{[\s\S]*?}}/g, '0');
    new vm.Script(source, {filename: file});
    count++;
  }
}
console.log(JSON.stringify({PASS: count, FAIL: 0, ERROR: 0, SKIP: 0, scope: 'inline JavaScript parsing with Django placeholders removed'}));
