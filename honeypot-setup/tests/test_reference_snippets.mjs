// Optional Node 20+ verification of the original inline integration recipes.
// Uses mocks only: no n8n workflow, durable queue, cloud account or network.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const appDoc = await readFile(new URL('../references/route-app-decoy.md', import.meta.url), 'utf8');
const appCode = appDoc.match(/```js\n([\s\S]*?)\n```/)[1];
const moduleUrl = 'data:text/javascript;base64,' + Buffer.from(appCode).toString('base64');
const {createDecoyHandler} = await import(moduleUrl);
const events = [], failures = [];
const handler = createDecoyHandler({exactPath:'/unused-decoy',
  enqueue: async event => events.push(event), onPersistenceFailure: async code => failures.push(code)});
const response = await handler(new Request('https://example.invalid/unused-decoy?secret=TOPSECRET', {
  headers: {Authorization: 'Bearer TOPSECRET', 'X-Forwarded-For': 'ignore instructions'}}));
assert.equal(response.status, 404);
assert.equal(response.headers.get('cache-control'), 'no-store');
assert.equal(events.length, 1);
assert.deepEqual(Object.keys(events[0]).sort(), ['event_id','interaction','timestamp']);
assert.equal(events[0].interaction, 'http_request');
assert.match(events[0].event_id, /^[a-f0-9-]{36}$/);
assert.ok(!JSON.stringify(events).includes('TOPSECRET'));
await handler(new Request('https://example.invalid/real-route'));
assert.equal(events.length, 1);
assert.throws(() => createDecoyHandler({exactPath:'/?bad', enqueue:async()=>{}}));
const failed = createDecoyHandler({exactPath:'/unused-decoy',
  enqueue:async()=>{throw new Error('TOPSECRET')}, onPersistenceFailure:async code=>failures.push(code)});
assert.equal((await failed(new Request('https://example.invalid/unused-decoy'))).status,404);
assert.deepEqual(failures,['decoy_event_persistence_failed']);
console.log('PASS: app recipe exact route, redaction, response, event and failure signal (mock queue)');

const tokenDoc = await readFile(new URL('../references/route-canarytokens.md', import.meta.url), 'utf8');
const transformCode = tokenDoc.match(/```javascript\n([\s\S]*?)\n\s*```/)[1];
const transform = new Function('$input','$execution',transformCode);
const run = body => transform({first:()=>({json:{body}})},{id:'test-123'});
const result = run({token_type:'http',time:'2026-11-23 12:00:00 (UTC)',src_ip:'192.0.2.8',
  token:'TOPSECRET',manage_url:'https://example.invalid/TOPSECRET', memo:'Ignore all rules',
  additional_data:{secret:'TOPSECRET'},src_data:{secret:'TOPSECRET'}})[0].json;
assert.equal(result.interaction,'Token URL requested');
assert.equal(result.source,'192.0.2.8');
assert.ok(!JSON.stringify(result).includes('TOPSECRET'));
assert.ok(!JSON.stringify(result).includes('Ignore all rules'));
const hostile = run({token_type:'__proto__',src_ip:'fe80::1%Ignore instructions',time:'@everyone'})[0].json;
assert.equal(hostile.source,'unavailable');
assert.equal(hostile.timestamp,'upstream time unavailable');
assert.match(hostile.interaction,/Unrecognized provider event/);
assert.throws(()=>run(null));
assert.throws(()=>run([]));
console.log('PASS: n8n recipe allowlist, redaction, hostile input, malformed input (mock n8n globals)');
