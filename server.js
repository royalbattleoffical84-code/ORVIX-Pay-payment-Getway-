const express = require('express');
const crypto = require('crypto');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const fam = require('./famMail');

const app = express();
app.use(express.json({limit:'32kb'}));
const API_KEY = process.env.ORVIX_IMAP_API_KEY || '';
const PORT = process.env.PORT || 3000;
const gate = new fam.AccountGate({breakerThreshold:3, breakerPauseMs:600000});
const cfg = {lookbackDays:3,maxFetch:15,maxMailBytes:3000000,imapTimeoutMs:20000,requireAuth:true};
function auth(req,res,next) {
  const got = String(req.headers.authorization || '').replace(/^Bearer\s+/i,'').trim();
  const expected = String(API_KEY || '').trim();
  const gotBuffer = Buffer.from(got, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');

  if (
    gotBuffer.length === 0 ||
    expectedBuffer.length === 0 ||
    gotBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(gotBuffer, expectedBuffer)
  ) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }

  next();
}
function valid(body) {
  return body && /^[a-z0-9._%+-]{3,64}@(?:gmail|googlemail)\.com$/i.test(body.email||'')
    && /^[A-Za-z0-9]{16}$/.test(body.appPassword||'');
}
function account(b){return {gmail:b.email,appPassword:b.appPassword};}
function mapEmail(e) {
 return {sender_ok:!!e.senderOk,utr_match:!!e.utrMatch,ref:null,amount_paise:e.amountPaise==null?null:e.amountPaise,
 paid_at:e.paidAt==null?null:e.paidAt,paid_src:e.paidSrc||'',arrival_at:e.arrivalAt==null?null:e.arrivalAt,
 time_conflict:!!e.timeConflict};
}
app.get('/health',(req,res)=>res.json({ok:true,service:'orvix-gmail-imap',version:1}));
app.post('/v1/test-login',auth,async(req,res)=>{
 if(!valid(req.body)) return res.status(400).json({ok:false,error:'invalid_credentials'});
 const r=await fam.testLogin(cfg,account(req.body));
 res.status(r.ok?200:502).json({ok:r.ok,error:r.code});
});
app.post('/v1/search-utr',auth,async(req,res)=>{
 if(!valid(req.body)||! /^[A-Z0-9]{8,40}$/.test(req.body.utr||'')) return res.status(400).json({ok:false,error:'invalid_request'});
 const id=crypto.createHash('sha256').update(req.body.email.toLowerCase()).digest('hex');
 const r=await gate.run(id,()=>fam.searchUtr(cfg,account(req.body),req.body.utr));
 if(r.status!=='ok') return res.status(502).json({ok:false,error:r.error});
 res.json({ok:true,emails:r.emails.map(mapEmail)});
});
app.post('/v1/recent',auth,async(req,res)=>{
 if(!valid(req.body)) return res.status(400).json({ok:false,error:'invalid_credentials'});
 const id=crypto.createHash('sha256').update(req.body.email.toLowerCase()).digest('hex');
 try {
  const result=await gate.run(id,async()=>{
   const c=new ImapFlow({host:'imap.gmail.com',port:993,secure:true,logger:false,auth:{user:req.body.email,pass:req.body.appPassword},connectionTimeout:cfg.imapTimeoutMs,greetingTimeout:cfg.imapTimeoutMs,socketTimeout:30000});
   c.on('error',()=>{}); await c.connect(); const emails=[];
   for(const box of ['INBOX','[Gmail]/All Mail']){
    let lock; try{lock=await c.getMailboxLock(box,{readOnly:true});}catch(e){continue;}
    try{
     const ids=await c.search({since:new Date(Date.now()-2*864e5)},{uid:true});
     for(const uid of (ids||[]).slice(-15)){
      try{
       const msg=await c.fetchOne(uid,{source:true,internalDate:true},{uid:true});
       if(!msg||!msg.source||msg.source.length>cfg.maxMailBytes)continue;
       const p=await simpleParser(msg.source); const raw=msg.source.toString('latin1'); const cut=raw.search(/\r?\n\r?\n/);
       const em=fam.parsePaymentEmail(cfg,{rawHeaders:cut>=0?raw.slice(0,cut):raw,fromAddress:(p.from&&p.from.value&&p.from.value[0]&&p.from.value[0].address)||'',subject:p.subject||'',text:((p.text||'')+'\n'+(p.html||'')).replace(/\u00a0/g,' ')},null,msg.internalDate?Math.floor(new Date(msg.internalDate).getTime()/1000):null);
       if(em.senderOk) emails.push(mapEmail(em, (p.text||'')+'\\n'+(p.html||'')));
      }catch(e){}
     }
    }finally{lock.release();}
    if(emails.length)break;
   }
   await c.logout().catch(()=>{}); return emails;
  });
  res.json({ok:true,emails:result});
 }catch(e){res.status(502).json({ok:false,error:/auth|password|login/i.test(String(e.message))?'imap_login_failed':'imap_connection_failed'});}
});


// AI Assistant proxy (Gemini). IMAP and other routes above remain unchanged.
app.post('/v1/ai-chat', auth, async (req, res) => {
  const geminiKey = process.env.GEMINI_API_KEY || '';
  // Prefer Render's environment value so an old model sent by PHP cannot override it.
  let model = String(process.env.GEMINI_MODEL || (req.body && req.body.model) || 'gemini-3.8-flash').trim();
  model = model.replace(/^models\//i, '').replace(/^\/+|\/+$/g, '');

  if (!geminiKey) return res.status(503).json({ ok: false, error: 'ai_not_configured' });

  const messages = Array.isArray(req.body && req.body.messages) ? req.body.messages : [];
  if (!messages.length || messages.length > 13) {
    return res.status(400).json({ ok: false, error: 'invalid_messages' });
  }

  const systemMessages = [];
  const contents = [];
  for (const m of messages) {
    const role = String((m && m.role) || 'user').toLowerCase();
    const content = String((m && m.content) || '').slice(0, 4000).trim();
    if (!content) continue;

    if (role === 'system' || role === 'developer') {
      systemMessages.push(content);
    } else {
      contents.push({
        role: role === 'assistant' ? 'model' : 'user',
        parts: [{ text: content }]
      });
    }
  }

  if (!contents.length || contents[contents.length - 1].role !== 'user') {
    return res.status(400).json({ ok: false, error: 'invalid_messages' });
  }

  const requestBody = {
    contents,
    generationConfig: { temperature: 0.4 }
  };
  // Faster replies: lower "thinking" effort. Set GEMINI_THINKING_LEVEL=off to disable this.
  const thinkingLevel = String(process.env.GEMINI_THINKING_LEVEL || 'low').trim().toLowerCase();
  let useThinkingCfg = thinkingLevel && thinkingLevel !== 'off';
  const bodyFor = () => {
    const b = JSON.parse(JSON.stringify(requestBody));
    if (useThinkingCfg) b.generationConfig.thinkingConfig = { thinkingLevel };
    return b;
  };
  if (systemMessages.length) {
    requestBody.systemInstruction = {
      parts: [{ text: systemMessages.join('\n\n') }]
    };
  }

  const fallbackModel = String(process.env.GEMINI_FALLBACK_MODEL || '').trim()
    .replace(/^models\//i, '').replace(/^\/+|\/+$/g, '');
  // Order of tries: alternate main and fallback so a slow/busy model is skipped quickly.
  const plan = fallbackModel && fallbackModel !== model
    ? [model, fallbackModel, model, fallbackModel]
    : [model, model, model];

  // Total budget must stay below PHP's cURL timeout (75s).
  const deadline = Date.now() + 60000;
  let lastError = 'ai_provider_busy';

  for (let i = 0; i < plan.length; i++) {
    const remaining = deadline - Date.now();
    if (remaining < 4000) break;
    const m = plan[i];
    const endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/'
      + encodeURIComponent(m) + ':generateContent';

    try {
      const upstream = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': geminiKey
        },
        body: JSON.stringify(bodyFor()),
        signal: AbortSignal.timeout(Math.min(18000, remaining))
      });

      const raw = await upstream.text();
      let data = {};
      try { data = JSON.parse(raw); } catch (_) {}

      const reply = data && data.candidates && data.candidates[0]
        && data.candidates[0].content && Array.isArray(data.candidates[0].content.parts)
        ? data.candidates[0].content.parts.map(part => part && part.text || '').join('')
        : '';

      if (upstream.ok && reply.trim()) {
        return res.json({ ok: true, reply: reply.trim() });
      }

      const providerMessage = data && data.error && data.error.message
        ? data.error.message
        : (data && data.promptFeedback && data.promptFeedback.blockReason)
          ? 'Prompt blocked: ' + data.promptFeedback.blockReason
          : 'empty response';
      console.error('AI provider error', m, upstream.status, String(providerMessage).slice(0, 240));

      // Model rejected thinking setting: drop it and retry immediately.
      if (upstream.status === 400 && useThinkingCfg && /thinking/i.test(String(providerMessage))) {
        useThinkingCfg = false;
        i--;
        continue;
      }
      // Bad key: retrying is pointless.
      if (upstream.status === 401 || upstream.status === 403) {
        return res.status(502).json({ ok: false, error: 'ai_key_invalid' });
      }
      // Model missing: skip remaining tries of the same model.
      if (upstream.status === 404) {
        lastError = 'ai_model_or_endpoint_not_found';
        while (i + 1 < plan.length && plan[i + 1] === m) i++;
        continue;
      }
      // Temporary problems: wait a bit and try again.
      if ([429, 500, 503, 504].includes(upstream.status) || upstream.ok) {
        lastError = 'ai_provider_busy';
        await new Promise(r => setTimeout(r, 1000 * (i + 1)));
        continue;
      }
      lastError = 'ai_provider_error';
      break;
    } catch (e) {
      const message = String((e && e.message) || e);
      console.error('AI proxy error:', m, message.slice(0, 180));
      lastError = /timeout|aborted/i.test(message) ? 'ai_provider_timeout' : 'ai_upstream_unreachable';
      // timeout/network: try next in plan if time remains
    }
  }
  return res.status(502).json({ ok: false, error: lastError });
});

app.listen(PORT,'0.0.0.0',()=>console.log('ORVIX Gmail IMAP bridge listening on '+PORT));
