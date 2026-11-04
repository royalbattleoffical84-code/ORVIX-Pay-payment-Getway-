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
  const got = String(req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  if (!API_KEY || !got || !crypto.timingSafeEqual(Buffer.from(got),Buffer.from(API_KEY))) return res.status(401).json({ok:false,error:'unauthorized'});
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
app.listen(PORT,'0.0.0.0',()=>console.log('ORVIX Gmail IMAP bridge listening on '+PORT));
