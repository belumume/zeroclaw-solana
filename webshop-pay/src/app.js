
function b64urlDecode(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';try{return decodeURIComponent(escape(atob(s)))}catch(e){return atob(s)}}
var el=function(id){return document.getElementById(id)};
var p=new URLSearchParams(location.search);
var url=p.get('u')?b64urlDecode(p.get('u')):(p.get('url')||'');
// Language. The shop quotes a Brazilian customer in Portuguese, so the checkout must not
// switch to English at the exact moment money moves; that break of character lands on the
// one screen where a payer decides whether to trust the page. Precedence: an explicit
// ?lang= the agent can set from the conversation, then the browser's own preference, then
// English. Only UI chrome is translated. The recipient address, the amount and the asset
// name are never passed through here, because a translation layer must not be able to
// alter anything the customer is approving.
var STR={pt:{
 title:'Pagar com Solana',
 payment:'Pagamento',
 connect:'Conectar carteira e pagar',
 orscan:'OU ESCANEIE COM A CARTEIRA DO CELULAR',
 scanhint:'Abra a Phantom ou a Solflare no seu celular e escaneie.',
 to:'para',
 copy:'Copiar link do Solana Pay',
 copied:'Copiado ✓',
 qrbig:'(QR grande demais)',
 invalid:'Este link não contém um pedido de pagamento Solana válido.',
 refused:'Recusado',
 refusedmsg:'Este link paga um endereço que não é desta loja. Nada foi enviado. Peça um link novo à loja.',
 linkwanted:'o link pedia: ',
 shopis:' / a loja é: ',
 refusednet:'Este link usa um token que esta loja não aceita. Nada foi enviado. Peça um link novo à loja.',
 linktoken:'token do link: ',
 refusedpaid:'Este pedido já foi pago. Nada foi enviado. Peça um link novo à loja se precisar pagar de novo.',
 paidamt:'pago: ',
 paidtx:'transação: ',
 amtwallet:'(valor definido na sua carteira)',
 connecting:'Conectando a carteira…',
 loadinglibs:'Carregando as bibliotecas da Solana…',
 building:'Preparando a transferência…',
 approve:'Aprove o pagamento na sua carteira…',
 // "Enviado", not "Pago". The wallet has broadcast and nothing has confirmed yet, and this line
 // is on screen for the whole confirmation window, so calling it paid here is the same overclaim
 // the timeout state below exists to avoid.
 confirming:'Enviado. Confirmando on-chain…',
 confirmwait:'Ainda confirmando… ',
 confirmslow:'Enviado, mas a confirmação está demorando mais que o normal. O pagamento pode ter sido concluído. Confira a transação antes de pagar de novo, ou recarregue esta página.',
 chainfailed:'A rede informou que esta transação falhou, então a transferência não foi feita. Recarregue esta página para tentar de novo.',
 paid:'✓ Pago',
 failed:'O pagamento não foi concluído: ',
 explorer:'Ver no explorer',
 holds:'Esta carteira tem ',
 hint:'No computador: clique em <b>Conectar carteira e pagar</b> (extensão Phantom ou Solflare). No celular: escaneie o QR com o app da sua carteira. Esta loja funciona na mainnet: o pagamento é em USDC de verdade e a carteira precisa de um pouco de SOL para a taxa.'
}};
var LANG=(function(){
  var q=(p.get('lang')||'').toLowerCase();
  if(q)return q.indexOf('pt')===0?'pt':'en';
  var n=(navigator.language||'').toLowerCase();
  return n.indexOf('pt')===0?'pt':'en';
})();
function T(k,en){var d=STR[LANG];return (d&&d[k])||en}
(function applyLang(){
  if(LANG==='en')return;
  document.documentElement.lang='pt-BR';
  var sel=function(s){return document.querySelector(s)};
  var n;
  if(el('pay'))el('pay').textContent=T('connect');
  if(el('copy'))el('copy').textContent=T('copy');
  if((n=sel('.or')))n.textContent=T('orscan');
  if((n=sel('.scan')))n.textContent=T('scanhint');
  if((n=sel('.hint')))n.innerHTML=T('hint');
  // "to <span id=recip>" - replace only the leading text node, never the address span.
  if((n=sel('.recip'))&&n.firstChild&&n.firstChild.nodeType===3)n.firstChild.nodeValue=T('to')+' ';
  document.title=T('title','Pay with Solana');
})();
// The one address this page will ever pay. Pinned here, in the page the customer
// actually loads, because every layer above it is advisory: the agent composes the
// link, and an agent that has been talked into a different recipient composes a
// perfectly well-formed link to it. Truncated display ("C331…iLHJ") is exactly what
// makes a swapped address survive a glance, so a mismatch is refused rather than
// shown, and the full address is rendered on the happy path.
var MERCHANT='C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ';
// ONE endpoint, and the reason it is not api.mainnet-beta.solana.com is measured rather than
// stylistic.
//
// That host returns HTTP 403 to any request carrying an Origin header -- that is, to EVERY browser
// fetch, from every origin including this page's own. Same host and same second, a request without
// the header returns 200. The rejection is protocol-agnostic: the websocket handshake is refused
// with the same 403 once a browser sends Origin, which every browser does. So BOTH halves of the
// desktop pay path were dead there, not only the settlement read.
//
//   host                          HTTP no Origin   HTTP +Origin   WS no Origin   WS +Origin
//   api.mainnet-beta.solana.com        200             403           OPEN           403
//   solana-rpc.publicnode.com          200             200           OPEN           OPEN
//
// That table is why the desktop "connect wallet and pay" button had been broken since the shop
// moved to mainnet while every phone payment worked: scanning the QR hands the solana: URL to the
// wallet, which builds and submits the transaction itself and never touches this page's RPC.
//
// A CORRECTION, recorded rather than quietly applied. This constant was left pointing at the 403
// host on the stated grounds that "that host's websocket does not open (measured, no handshake in
// 8s)". That measurement does not reproduce: the handshake opens in 0.36s WITH an Origin header
// and accepts slotSubscribe. The premise the two-endpoint split rested on is refuted, so the two
// collapse back into one rather than sitting at the same value under different names.
//
// Keyless and unauthenticated on purpose: this is static HTML served to anyone, so an RPC key
// pasted here would be a published credential. Measured under load rather than assumed: 40
// back-to-back calls at 4.8 rps all returned 200, against the ~0.5 rps one payment generates. A
// throttle is absorbed rather than avoided, because rpc() returns null for it and every caller
// already reads null as "change nothing" or "ask again".
//
// THIRD-PARTY TRUST, declared rather than implied: this endpoint answers READS. It never signs and
// never broadcasts, the wallet does both, so a hostile answer cannot misdirect money: the
// recipient, the mint and the amount are pinned in this page and shown again by the wallet before
// the customer approves. What a hostile answer can do is refuse a good link, or withhold a
// confirmation the page then reports as unconfirmed rather than as paid. Both are recoverable in
// one message to the shop, and neither moves funds.
var RPC='https://solana-rpc.publicnode.com';
// Asset names come from THIS map, keyed by mint address, and never from the mint's own
// on-chain metadata. A mint can call itself whatever it likes, so reading the symbol off
// the token would let a worthless mint present itself as USDC next to an amount the
// customer is about to approve. An unknown mint stays the generic word, which is the
// honest thing to show when we cannot name the asset ourselves.
//
// This map is also the settleable set. A mint that is not in it is refused outright rather
// than rendered with a cautionary label, because a label sits next to a live Pay button and
// a customer can click past it into an opaque getMint failure. The page pays on mainnet, so
// the devnet mint is not listed and a stale devnet link now gets the same clean refusal a
// wrong recipient gets: one door, one mechanism, nothing sent.
var KNOWN_MINTS={
 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v':'USDC'
};
function assetName(mint){return KNOWN_MINTS[mint]||'token'}
var recip='',amount='',label=T('payment','Payment'),message='',token='',reference='';
function status(m,cls){el('status').textContent=m;el('status').className='status '+(cls||'')}
// One refusal card, three callers. Every one builds with textContent rather than innerHTML
// because the detail lines echo attacker-controlled bytes straight out of the link, and now also
// a signature out of an RPC response.
//
// `opts` exists so the already-paid case can come through this same door rather than growing a
// second one. It changes only presentation: a card the customer should read as good news must not
// arrive in the red error style, because "your order is already paid" and "this link is trying to
// rob you" are opposite facts and the page has exactly one chance to say which. The mechanism is
// unchanged in all three cases -- clear the card, no Pay button, textContent throughout -- and
// both existing callers pass no opts, so their DOM is byte-identical to before.
function refuse(msg,detail,opts){
  opts=opts||{};
  var c=el('card');c.textContent='';
  var eh=document.createElement('h1');eh.textContent=opts.heading||T('refused','Refused');c.appendChild(eh);
  if(opts.big){var eb=document.createElement('div');eb.className='paid';eb.textContent=opts.big;c.appendChild(eb);}
  var ep=document.createElement('p');ep.className='msg';ep.textContent=msg;c.appendChild(ep);
  // opts.wrap adds break opportunities inside an unbreakable run. Only the already-paid card asks
  // for it, because only it renders an 88-char signature; the two address refusals must keep the
  // exact layout their plate was measured against.
  (Array.isArray(detail)?detail:[detail]).forEach(function(d){
    var ed=document.createElement('div');ed.className=opts.wrap?'recip brk':'recip';ed.textContent=d;c.appendChild(ed);
  });
  // Same signature gate as the in-session paid card: a signature reaching an href is re-validated
  // for shape and encoded, so a hostile RPC cannot steer where this link points.
  if(opts.link&&isSig(opts.link)){
    var ea=document.createElement('a');ea.className='link';ea.target='_blank';ea.rel='noopener noreferrer';
    ea.href='https://explorer.solana.com/tx/'+encodeURIComponent(opts.link);
    ea.textContent=T('explorer','View on explorer');c.appendChild(ea);
  }
  c.className=opts.cls||'card err';
}
if(!url||url.indexOf('solana:')!==0){el('card').textContent=T('invalid','No valid Solana Pay request in this link.');el('card').className='card err';}
else{
  var m=url.match(/^solana:([^?]+)\??(.*)$/);recip=m?m[1]:'';var q=new URLSearchParams(m?m[2]:'');
  amount=q.get('amount')||'';label=q.get('label')||T('payment','Payment');message=q.get('message')||'';token=q.get('spl-token')||'';reference=q.get('reference')||'';
  if(recip!==MERCHANT){
    refuse(T('refusedmsg','This link pays an address that is not this shop. Nothing has been sent. Ask the shop for a new link.'),
           T('linkwanted','link wanted: ')+recip+T('shopis',' / shop is: ')+MERCHANT);
  }else if(token&&!KNOWN_MINTS[token]){
    // A mint this page cannot settle. Refused rather than labelled: a label sits beside a live
    // Pay button, and the customer who clicks it gets an opaque failure deep in the wallet.
    refuse(T('refusednet','This link is for a token this shop cannot accept. Nothing has been sent. Ask the shop for a new link.'),
           T('linktoken','link token: ')+token);
  }else{
  el('label').textContent=label;
  el('amt').textContent=amount?(amount+' '+(token?assetName(token):'SOL')):T('amtwallet','(amount set in your wallet)');
  el('msg').textContent=message;if(!message)el('msg').style.display='none';
  el('recip').textContent=recip;
  try{var qr=qrcode(0,'M');qr.addData(url);qr.make();el('qr').innerHTML=qr.createImgTag(10,8);}catch(e){el('qr').textContent=T('qrbig','(QR too large)');}
  el('copy').onclick=function(){navigator.clipboard.writeText(url).then(function(){el('copy').textContent=T('copied','Copied ✓');setTimeout(function(){el('copy').textContent=T('copy','Copy Solana Pay link')},1500)})};
  el('pay').onclick=connectAndPay;
  checkAlreadyPaid();
  }
}
function isSig(s){return typeof s==='string'&&/^[1-9A-HJ-NP-Za-km-z]{64,100}$/.test(s)}
function isPubkey(s){return typeof s==='string'&&/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s)}
// --- has this order already been paid? -------------------------------------------------------
//
// A Solana Pay reference key is SINGLE-USE by design: it rides the transfer as a read-only
// non-signer account, so getSignaturesForAddress on the reference returns the transaction that
// settled this order. A page that keeps offering to pay a spent link will take a SECOND transfer
// for one order, the customer cannot tell, and the shop then owes a refund -- which is the one
// path in this system that touches funds and sits behind a human checkpoint. So the page asks.
//
// The check lives HERE and not only in the agent because the link is a URL: a customer can open
// it days later out of chat history with no agent involved.
//
// FAIL OPEN ON THE NETWORK, CLOSED ONLY ON A POSITIVE FINDING. This runs AFTER the payable card
// has rendered and can only ever replace it, so an unreachable, slow, rate-limited or malformed
// endpoint leaves a good link fully payable. That direction is deliberate: refusing a real order
// because a public RPC was busy would be a worse failure than the one being fixed, and it would
// be invisible to the shop, whereas the untaken second payment simply does not happen. The cost
// of that choice, stated rather than hidden: for the few hundred milliseconds the call is in
// flight, a spent link is still clickable. The realistic customer is reading the page for longer
// than that, and the shop's own watcher is the authority either way.
//
// One JSON-RPC POST. Returns the result, or null for ANY failure -- offline, DNS, abort, HTTP
// error, a rate-limit 429, malformed JSON, or a JSON-RPC error object. Null is the only failure
// signal because every caller treats "the chain did not answer" identically: change nothing.
function rpc(method,params){
  var ctl=(typeof AbortController!=='undefined')?new AbortController():null;
  var timer=ctl?setTimeout(function(){ctl.abort()},6000):0;
  var opts={method:'POST',headers:{'content-type':'application/json'},
            body:JSON.stringify({jsonrpc:'2.0',id:1,method:method,params:params})};
  if(ctl)opts.signal=ctl.signal;
  return fetch(RPC,opts)
    .then(function(r){return r.ok?r.json():null})
    .then(function(j){return (j&&!j.error&&j.result!==undefined&&j.result!==null)?j.result:null})
    .catch(function(){return null})
    .then(function(v){if(timer)clearTimeout(timer);return v});
}
// The settling signature, or null. Same gate as plugins/payment-watch/src/watch.rs, which is the
// component that actually credits the order: commitment "confirmed", and an entry whose `err` is
// unset. A failed transaction moved no funds and must never read as a settlement.
function settledSignature(){
  // Validated before the network, as watch.rs validates its address before any RPC call: a
  // reference lifted out of a hostile link never reaches an endpoint unless it is a pubkey.
  if(!isPubkey(reference))return Promise.resolve(null);
  return rpc('getSignaturesForAddress',[reference,{limit:20,commitment:'confirmed'}]).then(function(list){
    if(!Array.isArray(list))return null;
    // The node answers newest-first, so walk backwards to reach the OLDEST entry: the transaction
    // that settled this order rather than a later one that happens to touch the same key.
    for(var i=list.length-1;i>=0;i--){
      var e=list[i];
      if(e&&!e.err&&isSig(e.signature))return e.signature;
    }
    return null;
  });
}
// The full ordered account-key list, static keys then any address-lookup-table addresses. This is
// the index space the lamport balance arrays are aligned with; reading only the static half would
// misindex a v0 transaction. Mirrors account_keys() in watch.rs.
function accountKeys(tx){
  var out=[],msg=((tx.transaction||{}).message)||{},loaded=((tx.meta||{}).loadedAddresses)||{};
  (msg.accountKeys||[]).forEach(function(k){out.push((typeof k==='string')?k:(k&&k.pubkey))});
  ['writable','readonly'].forEach(function(s){(loaded[s]||[]).forEach(function(k){out.push(k)})});
  return out;
}
// What the merchant ACTUALLY received, read out of the settling transaction by balance delta the
// way watch.rs does it, rather than echoed back from the link. The link states what was
// REQUESTED; only the chain states what was PAID, and on a receipt those are different claims.
// Null when the transaction cannot be read or does not credit this shop, in which case the card
// still refuses and simply names no figure.
function merchantCredit(tx){
  var meta=tx&&tx.meta;if(!meta||meta.err)return null;
  if(token){
    var side=function(arr){
      var sum=0,dec=null,seen=false;
      (arr||[]).forEach(function(b){
        if(!b||b.owner!==MERCHANT||b.mint!==token)return;
        seen=true;var u=b.uiTokenAmount||{};
        if(dec===null&&typeof u.decimals==='number')dec=u.decimals;
        var a=parseFloat(u.amount);if(isFinite(a))sum+=a;
      });
      return {sum:sum,dec:dec,seen:seen};
    };
    var pre=side(meta.preTokenBalances),post=side(meta.postTokenBalances);
    if(!pre.seen&&!post.seen)return null;
    var dec=(post.dec===null?pre.dec:post.dec);if(dec===null)return null;
    var net=post.sum-pre.sum;if(!(net>0))return null;
    return trimZeros((net/Math.pow(10,dec)).toFixed(dec))+' '+assetName(token);
  }
  var idx=accountKeys(tx).indexOf(MERCHANT);if(idx<0)return null;
  var p=(meta.preBalances||[])[idx],q=(meta.postBalances||[])[idx];
  if(typeof p!=='number'||typeof q!=='number'||!(q-p>0))return null;
  return trimZeros(((q-p)/1e9).toFixed(9))+' SOL';
}
function trimZeros(s){return s.indexOf('.')<0?s:s.replace(/0+$/,'').replace(/\.$/,'')}
function checkAlreadyPaid(){
  settledSignature().then(function(sig){
    if(!sig)return;
    // Only now, and only because the page is about to refuse, does it spend a second round trip.
    // The payable path -- the common one, and the one the demo films -- stays at exactly one call.
    return rpc('getTransaction',[sig,{encoding:'jsonParsed',commitment:'confirmed',maxSupportedTransactionVersion:0}])
      .then(function(tx){
        var detail=[],paid=tx?merchantCredit(tx):null;
        if(paid)detail.push(T('paidamt','paid: ')+paid);
        detail.push(T('paidtx','tx: ')+sig);
        refuse(T('refusedpaid','This order has already been paid. Nothing has been sent. Ask the shop for a new link if you need to pay again.'),
               detail,{heading:'Solana Pay',big:T('paid','✓ Paid'),cls:'card',link:sig,wrap:true});
      });
  });
}
function showPaid(sig){
  var card=el('card');card.textContent='';
  var h=document.createElement('h1');h.textContent='Solana Pay';card.appendChild(h);
  var d=document.createElement('div');d.className='paid';d.textContent=T('paid','✓ Paid');card.appendChild(d);
  var pl=document.createElement('p');pl.className='msg';pl.textContent=label;card.appendChild(pl);
  // No ?cluster= query: mainnet-beta is the explorer's default. This link is the customer's
  // receipt for a real payment, so a stale cluster param would point their proof at a chain
  // the transaction was never on -- a dead link at the exact moment it has to hold.
  if(isSig(sig)){var a=document.createElement('a');a.className='link';a.target='_blank';a.rel='noopener noreferrer';a.href='https://explorer.solana.com/tx/'+encodeURIComponent(sig);a.textContent=T('explorer','View on explorer');card.appendChild(a);}
}
// A status line carrying an explorer link, for the two outcomes that are neither a confirmed
// payment nor a clean pre-broadcast failure. Same signature gate as everywhere else: a signature
// reaching an href is re-validated for shape and encoded, so a hostile RPC cannot steer where this
// link points. The signature is NOT rendered as text -- an 88-char base58 run has no break
// opportunity and measured +286px of horizontal scroll when one was last put on this card, and the
// opening shot's plate is keyed to there being none.
function statusWithTx(msg,cls,sig){
  var s=el('status');s.textContent=msg;s.className='status '+(cls||'');
  if(isSig(sig)){
    s.appendChild(document.createTextNode(' '));
    var a=document.createElement('a');a.className='link';a.target='_blank';a.rel='noopener noreferrer';
    a.href='https://explorer.solana.com/tx/'+encodeURIComponent(sig);
    a.textContent=T('explorer','View on explorer');s.appendChild(a);
  }
}
// Confirmation by POLLING plain HTTPS, not by opening a websocket, and the reason is about WHEN a
// failure lands rather than about which endpoint works.
//
// By the time this runs the wallet has already broadcast and the customer's money has already
// moved. Anything that throws from here is therefore reporting on a transfer that may well have
// succeeded, and the catch in connectAndPay renders a throw as "the payment did not complete" --
// a FALSE claim about a settled transfer, which is the worst sentence this page can show. A
// websocket adds a second transport, with its own handshake and its own failure modes, on top of
// the HTTPS this page has just proven it can reach (it built the transaction over it). That
// concentrates a NEW way to fail at the exact moment the page can least afford one. Polling reuses
// the transport that is already working, and rpc() cannot throw, so the post-broadcast path has no
// route into the catch at all.
//
// Three terminal states, and the third is the point. CONFIRMED. FAILED-ON-CHAIN, where the network
// itself reports the transaction errored and no transfer happened. And UNKNOWN, where the window
// ran out: not paid, not failed, and it must never be rendered as either.
//
// 45 attempts at 2s is ~90s, which is roughly the life of a blockhash: past that an unlanded
// transaction can no longer land, so continuing to poll would only delay an answer that is not
// coming. Every failure mode in between -- offline, DNS, abort, a 429 -- arrives as a null from
// rpc() and is read as "ask again", so a throttle degrades this into a slower confirmation and
// never into a false verdict.
var CONFIRM_INTERVAL_MS=2000,CONFIRM_ATTEMPTS=45;
async function awaitConfirmation(sig){
  for(var i=0;i<CONFIRM_ATTEMPTS;i++){
    var r=await rpc('getSignatureStatuses',[[sig],{searchTransactionHistory:true}]);
    var st=(r&&r.value&&r.value[0])||null;
    if(st){
      // A failed transaction moved no funds and must never read as a settlement. Same gate as the
      // already-paid check above and as plugins/payment-watch/src/watch.rs.
      if(st.err)return 'failed';
      var c=st.confirmationStatus;
      // "confirmed" is the bar the watcher credits an order at; "processed" is not, so a
      // transaction seen but not yet confirmed keeps polling rather than resolving early.
      if(c==='confirmed'||c==='finalized')return 'confirmed';
    }
    status(T('confirmwait','Still confirming… ')+Math.round((i+1)*CONFIRM_INTERVAL_MS/1000)+'s');
    await new Promise(function(f){setTimeout(f,CONFIRM_INTERVAL_MS)});
  }
  return 'unknown';
}
// The three outcomes, rendered. Extracted from connectAndPay rather than left inline so the mapping
// from outcome to what the customer actually sees can be driven directly, including the two states
// a live run cannot produce on demand.
//
// TWO INVARIANTS, and they are the whole reason this is a function. Only 'confirmed' renders as
// paid, so a timeout can never claim a payment that has not confirmed. And NOTHING here re-enables
// the Pay button, in either failing case.
//
// The second is deliberate even for 'failed', where nothing moved and a retry would be safe. The
// authority on whether this order is still payable is the settlement check that runs on LOAD, which
// refuses a reference that has already settled. Routing a retry through a reload therefore reuses a
// proven guard instead of letting one status read decide it, and re-offering Pay here is exactly how
// one order comes to take two transfers.
function renderOutcome(outcome,sig){
  if(outcome==='confirmed'){showPaid(sig);return;}
  // Disabled HERE rather than left to connectAndPay having done it on the way in. The comment
  // above claims this function never hands the button back, and until this line that claim was
  // true only because a DIFFERENT function forty lines away happened to disable it first. An
  // invariant asserted in one place and enforced in another is the shape that silently stops
  // holding; this makes it local, and the harness drives renderOutcome directly to prove it.
  if(el('pay'))el('pay').disabled=true;
  statusWithTx(outcome==='failed'
    ? T('chainfailed','The network reported this transaction as failed, so the transfer did not go through. Reload this page to try again.')
    : T('confirmslow','Sent, but confirmation is taking longer than usual. The payment may still have gone through. Check the transaction before paying again, or reload this page.'),
    outcome==='failed'?'err':'',sig);
}
async function connectAndPay(){
  var provider=(window.phantom&&window.phantom.solana)||window.solflare||window.solana;
  if(!provider){status('No Solana wallet extension detected in this browser. Install Phantom or Solflare (desktop), or scan the QR above with a phone wallet.','err');return;}
  el('pay').disabled=true;status(T('loadinglibs','Loading Solana libraries…'));
  try{
    var web3=await import('https://esm.sh/@solana/web3.js@1.95.3');
    // Mainnet, from the single constant at the top. Used for reads only -- getMint, the two
    // getAccount preflights and getLatestBlockhash. It never signs and never broadcasts: the
    // wallet does both, via its own RPC. web3.js opens its websocket lazily, on the first
    // subscription, and this page makes none now that confirmation is a poll, so no websocket is
    // ever opened here.
    var conn=new web3.Connection(RPC,'confirmed');
    status(T('connecting','Connecting wallet…'));
    var resp=await provider.connect();
    var payer=resp.publicKey||provider.publicKey;
    var recipientPk=new web3.PublicKey(recip);
    var refPk=reference?new web3.PublicKey(reference):null;
    var tx=new web3.Transaction();
    if(token){
      status(T('building','Building token transfer…'));
      var spl=await import('https://esm.sh/@solana/spl-token@0.4.9');
      var mint=new web3.PublicKey(token);
      var mintInfo=await spl.getMint(conn,mint);
      var fromAta=await spl.getAssociatedTokenAddress(mint,payer);
      var toAta=await spl.getAssociatedTokenAddress(mint,recipientPk);
      var amt=BigInt(Math.round(parseFloat(amount)*Math.pow(10,mintInfo.decimals)));
      // same allowlist as the headline, so the two cannot drift into disagreeing
      // about what the customer is being asked to pay.
      var knownName=KNOWN_MINTS[token];
      // preflight: the payer must actually hold the token, else the wallet returns a cryptic
      // "Internal error". Detect it and say exactly what is short, by how much.
      var have=-1n;try{have=(await spl.getAccount(conn,fromAta)).amount;}catch(e2){have=-1n;}
      if(have<amt){
        var haveStr=have<0n?'0':(Number(have)/Math.pow(10,mintInfo.decimals)).toString();
        var needStr=(Number(amt)/Math.pow(10,mintInfo.decimals)).toString();
        // No faucet line on mainnet: there is no faucet, and pointing a customer at one for
        // real USDC would be advice that cannot be followed. State the shortfall and stop.
        status(T('holds','This wallet holds ')+haveStr+(knownName?' '+knownName:' of the requested token')+', needs '+needStr+'. Fund this wallet on Solana mainnet, then retry.','err');
        el('pay').disabled=false;return;
      }
      // ensure the recipient's token account exists (idempotent; payer funds the tiny rent) so
      // the transfer can never fail on a missing destination account.
      try{await spl.getAccount(conn,toAta);}catch(e3){tx.add(spl.createAssociatedTokenAccountIdempotentInstruction(payer,toAta,recipientPk,mint));}
      var ix=spl.createTransferCheckedInstruction(fromAta,mint,toAta,payer,amt,mintInfo.decimals);
      if(refPk)ix.keys.push({pubkey:refPk,isSigner:false,isWritable:false});
      tx.add(ix);
    }else{
      var ix2=web3.SystemProgram.transfer({fromPubkey:payer,toPubkey:recipientPk,lamports:Math.round(parseFloat(amount)*web3.LAMPORTS_PER_SOL)});
      if(refPk)ix2.keys.push({pubkey:refPk,isSigner:false,isWritable:false});
      tx.add(ix2);
    }
    tx.feePayer=payer;
    tx.recentBlockhash=(await conn.getLatestBlockhash()).blockhash;
    status(T('approve','Approve the payment in your wallet…'));
    var sig=await provider.signAndSendTransaction(tx);
    var s=(sig&&sig.signature)?sig.signature:sig;
    status(T('confirming','Sent. Confirming on-chain…'));
    renderOutcome(await awaitConfirmation(s),s);
  }catch(e){status(T('failed','Payment did not complete: ')+(e&&e.message?String(e.message):String(e)),'err');el('pay').disabled=false;}
}
