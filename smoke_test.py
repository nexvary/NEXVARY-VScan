from __future__ import annotations
import http.cookiejar, json, os, socket, sqlite3, subprocess, sys, threading, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parent; DB=ROOT/'smoke.db'; TOKEN=ROOT/'.smoke-token'; VERSION='1.7.5'
def port():
    s=socket.socket(); s.bind(('127.0.0.1',0)); p=s.getsockname()[1]; s.close(); return p
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        path=urllib.parse.urlsplit(self.path).path
        if path=='/.well-known/nexvary-verification.txt': body=TOKEN.read_text() if TOKEN.exists() else 'x'; ctype='text/plain'
        elif path=='/robots.txt': body='User-agent: *\nDisallow: /two\nSitemap: /sitemap.xml\n'; ctype='text/plain'
        elif path=='/sitemap.xml': body='<urlset><url><loc>http://127.0.0.1:%s/two</loc></url></urlset>'%self.server.server_port; ctype='application/xml'
        elif path=='/.well-known/security.txt': body='Contact: mailto:security@example.test'; ctype='text/plain'
        elif path=='/app.js': body='fetch("/api/v2/users"); const apiKey="1234567890abcdef1234567890abcdef";\n//# sourceMappingURL=app.js.map'; ctype='application/javascript'
        elif path=='/two': body='<html>Traceback demo</html>'; ctype='text/html'
        elif path=='/admin': body='<html>Admin console</html>'; ctype='text/html'
        else: body='<html><meta name="generator" content="NEXVARY-QA 2.4.1"><a href="/two?next=/home">Two</a><a href="/admin">Admin</a><script src="/app.js"></script><form method="post" action="/login"><input name="email"><input type="password" name="password"></form></html>'; ctype='text/html'
        self.send_response(200); self.send_header('Content-Type',ctype); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Set-Cookie','sid=abc'); self.end_headers(); self.wfile.write(body.encode())
def post(o,u,d): return o.open(urllib.request.Request(u,data=urllib.parse.urlencode(d).encode(),method='POST'),timeout=20)
def one(sql):
    for _ in range(80):
        try:
            with sqlite3.connect(DB) as c:
                r=c.execute(sql).fetchone()
                if r:return r
        except sqlite3.Error: pass
        time.sleep(.1)
    raise RuntimeError(sql)
def run_scan(o,base,tid):
    post(o,base+f'/targets/{tid}/request-scan',{}).read(); sid=one('select id from scan_requests order by id desc limit 1')[0]; post(o,base+f'/admin/scans/{sid}/approve',{'note':'QA'}).read(); post(o,base+f'/admin/scans/{sid}/run',{}).read(); return sid
def main():
    for p in (DB,TOKEN):
        try:p.unlink()
        except:pass
    ap,tp=port(),port(); srv=ThreadingHTTPServer(('127.0.0.1',tp),H); threading.Thread(target=srv.serve_forever,daemon=True).start(); env=os.environ.copy(); env.update({'DATABASE_URL':'sqlite:///./smoke.db','NEXVARY_ADMIN_PASSWORD':'ChangeMe123!','VSCAN_ALLOW_PRIVATE_TEST_TARGETS':'1','VSCAN_REQUEST_DELAY':'0'}); proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(ap)],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); base=f'http://127.0.0.1:{ap}'
    try:
        for _ in range(80):
            try:
                health=json.loads(urllib.request.urlopen(base+'/health',timeout=1).read())
                if health['version']==VERSION and health['stage']==1750: break
            except: time.sleep(.25)
        else: raise RuntimeError('health gate failed')
        jar=http.cookiejar.CookieJar(); o=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)); post(o,base+'/login',{'username':'admin','password':'ChangeMe123!'}).read(); post(o,base+'/targets',{'name':'QA','url':f'http://127.0.0.1:{tp}','owner':'NEXVARY'}).read(); tid,tok=one('select id,verification_token from targets order by id desc limit 1'); TOKEN.write_text(tok); post(o,base+f'/targets/{tid}/verify',{}).read()
        sid1=run_scan(o,base,tid)
        status,score,pages,reqs=one(f'select status,security_score,pages_crawled,requests_made from scan_requests where id={sid1}'); findings=one(f'select count(*) from findings where scan_request_id={sid1}')[0]; surface=one(f'select count(*) from surface_items where scan_request_id={sid1}')[0]; assert status=='completed' and pages>=2 and reqs>=5 and findings>=5 and surface>=8
        sid2=run_scan(o,base,tid)
        export=json.loads(o.open(base+f'/scans/{sid2}/export.json',timeout=20).read())
        assert export['stage']==1750 and export['mode']=='authorized-defensive'
        assert export['risk_intelligence']['confirmed']>=1 and export['quality_intelligence']['coverage_grade'] in {'High','Medium','Limited'}
        assert export['trend']['baseline_scan_id']==sid1 and export['trend']['persistent_count']>=1
        portfolio=json.loads(o.open(base+'/portfolio.json',timeout=20).read())
        assert portfolio['stage']==1750 and portfolio['portfolio']['targets_verified']==1 and portfolio['portfolio']['completed']>=2
        for path,marker in [('/','Executive Security Portfolio'),('/targets','Ownership & Control'),('/scan-center','All Scan Requests'),('/reports','Evidence Archive')]:
            page=o.open(base+path,timeout=20).read().decode(); assert marker in page
        sarif=json.loads(o.open(base+f'/scans/{sid2}/export.sarif',timeout=20).read()); assert sarif['version']=='2.1.0'
        print(f'LIVE E2E STAGE 1750 PASSED score={score} pages={pages} requests={reqs} findings={findings} surface={surface} portfolio={portfolio["portfolio"]["current_portfolio_score"]}')
    finally:
        srv.shutdown(); proc.terminate(); proc.wait(timeout=5)
        for p in (DB,TOKEN):
            try:p.unlink()
            except:pass
if __name__=='__main__': main()
