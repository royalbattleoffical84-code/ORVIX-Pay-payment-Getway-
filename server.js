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

  // timingSafeEqual throws RangeError when buffer lengths differ.
  // Check both buffers are non-empty and equal length before comparing.
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


// AI Assistant proxy (Gemini). Uses the same private bearer key as the IMAP bridge.
app.post('/v1/ai-chat', auth, async (req, res) => {
  try {
    const geminiKey = process.env.GEMINI_API_KEY || '';
    const model = String((req.body && req.body.model) || process.env.GEMINI_MODEL || 'gemini-2.5-flash').trim();
    const messages = Array.isArray(req.body && req.body.messages) ? req.body.messages : [];
    if (!geminiKey) return res.status(503).json({ ok: false, error: 'ai_not_configured' });
    if (!messages.length || messages.length > 13) return res.status(400).json({ ok: false, error: 'invalid_messages' });
    const safeMessages = messages.map(m => ({
      role: m && m.role === 'assistant' ? 'assistant' : 'user',
      content: String((m && m.content) || '').slice(0, 4000)
    })).filter(m => m.content.trim());
    if (!safeMessages.length || safeMessages[safeMessages.length - 1].role !== 'user') {
      return res.status(400).json({ ok: false, error: 'invalid_messages' });
    }
    const upstream = await fetch('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + geminiKey },
      body: JSON.stringify({ model, temperature: 0.4, messages: safeMessages }),
      signal: AbortSignal.timeout(40000)
    });
    const raw = await upstream.text();
    let data = {};
    try { data = JSON.parse(raw); } catch (_) {}
    const reply = data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
    if (!upstream.ok || typeof reply !== 'string' || !reply.trim()) {
      console.error('AI provider error', upstream.status, String((data.error && data.error.message) || 'empty response').slice(0, 180));
      return res.status(502).json({ ok: false, error: upstream.status === 401 || upstream.status === 403 ? 'ai_key_invalid' : 'ai_provider_error' });
    }
    return res.json({ ok: true, reply });
  } catch (e) {
    console.error('AI proxy error:', String((e && e.message) || e).slice(0, 180));
    return res.status(502).json({ ok: false, error: 'ai_upstream_unreachable' });
  }
});

app.listen(PORT,'0.0.0.0',()=>console.log('ORVIX Gmail IMAP bridge listening on '+PORT));
