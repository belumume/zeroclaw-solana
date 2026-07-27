
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
 amtwallet:'(valor definido na sua carteira)',
 connecting:'Conectando a carteira…',
 loadinglibs:'Carregando as bibliotecas da Solana…',
 building:'Preparando a transferência…',
 approve:'Aprove o pagamento na sua carteira…',
 confirming:'Pago. Confirmando on-chain…',
 paid:'✓ Pago',
 failed:'O pagamento não foi concluído: ',
 explorer:'Ver no explorer',
 holds:'Esta carteira tem ',
 hint:'No computador: clique em <b>Conectar carteira e pagar</b> (extensão Phantom ou Solflare). No celular: escaneie o QR com o app da sua carteira. Esta loja funciona na devnet, então a carteira precisa estar na devnet e ter um pouco de SOL de devnet.'
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
// Asset names come from THIS map, keyed by mint address, and never from the mint's own
// on-chain metadata. A mint can call itself whatever it likes, so reading the symbol off
// the token would let a worthless mint present itself as USDC next to an amount the
// customer is about to approve. An unknown mint stays the generic word, which is the
// honest thing to show when we cannot name the asset ourselves.
var KNOWN_MINTS={'4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU':'devnet USDC'};
function assetName(mint){return KNOWN_MINTS[mint]||'token'}
var recip='',amount='',label=T('payment','Payment'),message='',token='',reference='';
function status(m,cls){el('status').textContent=m;el('status').className='status '+(cls||'')}
if(!url||url.indexOf('solana:')!==0){el('card').textContent=T('invalid','No valid Solana Pay request in this link.');el('card').className='card err';}
else{
  var m=url.match(/^solana:([^?]+)\??(.*)$/);recip=m?m[1]:'';var q=new URLSearchParams(m?m[2]:'');
  amount=q.get('amount')||'';label=q.get('label')||T('payment','Payment');message=q.get('message')||'';token=q.get('spl-token')||'';reference=q.get('reference')||'';
  if(recip!==MERCHANT){
    el('card').textContent='';
    var eh=document.createElement('h1');eh.textContent=T('refused','Refused');el('card').appendChild(eh);
    var ep=document.createElement('p');ep.className='msg';
    ep.textContent=T('refusedmsg','This link pays an address that is not this shop. Nothing has been sent. Ask the shop for a new link.');
    el('card').appendChild(ep);
    var ed=document.createElement('div');ed.className='recip';
    ed.textContent=T('linkwanted','link wanted: ')+recip+T('shopis',' / shop is: ')+MERCHANT;
    el('card').appendChild(ed);
    el('card').className='card err';
  }else{
  el('label').textContent=label;
  el('amt').textContent=amount?(amount+' '+(token?assetName(token):'SOL')):T('amtwallet','(amount set in your wallet)');
  el('msg').textContent=message;if(!message)el('msg').style.display='none';
  el('recip').textContent=recip;
  try{var qr=qrcode(0,'M');qr.addData(url);qr.make();el('qr').innerHTML=qr.createImgTag(5,8);}catch(e){el('qr').textContent=T('qrbig','(QR too large)');}
  el('copy').onclick=function(){navigator.clipboard.writeText(url).then(function(){el('copy').textContent=T('copied','Copied ✓');setTimeout(function(){el('copy').textContent=T('copy','Copy Solana Pay link')},1500)})};
  el('pay').onclick=connectAndPay;
  }
}
function isSig(s){return typeof s==='string'&&/^[1-9A-HJ-NP-Za-km-z]{64,100}$/.test(s)}
function showPaid(sig){
  var card=el('card');card.textContent='';
  var h=document.createElement('h1');h.textContent='Solana Pay';card.appendChild(h);
  var d=document.createElement('div');d.className='paid';d.textContent=T('paid','✓ Paid');card.appendChild(d);
  var pl=document.createElement('p');pl.className='msg';pl.textContent=label;card.appendChild(pl);
  if(isSig(sig)){var a=document.createElement('a');a.className='link';a.target='_blank';a.rel='noopener noreferrer';a.href='https://explorer.solana.com/tx/'+encodeURIComponent(sig)+'?cluster=devnet';a.textContent=T('explorer','View on explorer');card.appendChild(a);}
}
async function connectAndPay(){
  var provider=(window.phantom&&window.phantom.solana)||window.solflare||window.solana;
  if(!provider){status('No Solana wallet extension detected in this browser. Install Phantom or Solflare (desktop), or scan the QR above with a phone wallet.','err');return;}
  el('pay').disabled=true;status(T('loadinglibs','Loading Solana libraries…'));
  try{
    var web3=await import('https://esm.sh/@solana/web3.js@1.95.3');
    var conn=new web3.Connection('https://api.devnet.solana.com','confirmed');
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
      // "Internal error". Detect it and say exactly what's wrong + where to get devnet USDC.
      var have=-1n;try{have=(await spl.getAccount(conn,fromAta)).amount;}catch(e2){have=-1n;}
      if(have<amt){
        var haveStr=have<0n?'0':(Number(have)/Math.pow(10,mintInfo.decimals)).toString();
        var needStr=(Number(amt)/Math.pow(10,mintInfo.decimals)).toString();
        status(T('holds','This wallet holds ')+haveStr+(knownName?' '+knownName:' of the requested token')+', needs '+needStr+'. Get free devnet USDC at faucet.circle.com (pick Solana Devnet, paste this wallet), then retry.','err');
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
    status(T('confirming','Paid. Confirming on-chain…'));
    await conn.confirmTransaction(s,'confirmed');
    showPaid(s);
  }catch(e){status(T('failed','Payment did not complete: ')+(e&&e.message?String(e.message):String(e)),'err');el('pay').disabled=false;}
}
