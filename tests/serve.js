#!/usr/bin/env node
// Static file server for the regression tests. Listens on 127.0.0.1 only; no dependencies.
//   node tests/serve.js [port]      then open http://127.0.0.1:8765/tests/run.html
// /latest redirects to the newest Taegis-NetFlow-Analyzer-*.html in the repo root.
const http=require('http'), fs=require('fs'), path=require('path');
const root=path.resolve(__dirname,'..'), port=+process.argv[2]||8765;
const TYPES={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.csv':'text/csv; charset=utf-8','.png':'image/png','.md':'text/plain; charset=utf-8'};
function latestBuild(){
  const ver=f=>f.match(/\d+/g).map(Number);
  return fs.readdirSync(root).filter(f=>/^Taegis-NetFlow-Analyzer-v[\d.]+\.html$/.test(f))
    .sort((a,b)=>{ const x=ver(a), y=ver(b); for(let i=0;i<Math.max(x.length,y.length);i++){ const d=(x[i]||0)-(y[i]||0); if(d) return d; } return 0; }).pop();
}
http.createServer((req,res)=>{
  const u=decodeURIComponent(req.url.split('?')[0]);
  if(u==='/latest'){ const b=latestBuild(); if(!b){ res.writeHead(404); return res.end('no build found'); } res.writeHead(302,{Location:'/'+b}); return res.end(); }
  const p=path.join(root,u);
  if(p!==root&&!p.startsWith(root+path.sep)){ res.writeHead(403); return res.end(); }
  fs.stat(p,(e,st)=>{
    if(e||!st.isFile()){ res.writeHead(404); return res.end('not found'); }
    res.writeHead(200,{'Content-Type':TYPES[path.extname(p)]||'application/octet-stream','Content-Length':st.size,'Cache-Control':'no-store'});
    fs.createReadStream(p).pipe(res);
  });
}).listen(port,'127.0.0.1',()=>console.log(`Regression tests: http://127.0.0.1:${port}/tests/run.html   (Ctrl+C to stop)`));
