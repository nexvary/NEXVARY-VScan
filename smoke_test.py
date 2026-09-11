from __future__ import annotations
import http.cookiejar, json, os, socket, sqlite3, subprocess, sys, threading, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parent; DB=ROOT/'smoke.db'; TOKEN=ROOT/'.smoke-token'; VERSION='0.5.0'
def port():
    s=socket.socket(); s.bind(('127.0.0.1',0)); p=s.getsockname()[1]; s.close(); return p
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        path=urllib.parse.urlsplit(self.path).path
        if path=='/.well-known/nexvary-verification.txt': body=TOKEN.read_text() if TOKEN.exists() else 'x'
        elif path=='/two': body='<html>Traceback demo</html>'
        else: body='<html><a href="/two?next=/home">Two</a><script src="/app.js"></script><form method="post" action="/login"><input name="email"></form></html>'
        self.send_response(200); self.send_header('Content-Type','text/html'); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Set-Cookie','sid=abc'); self.end_headers(); self.wfile.write(body.encode())
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
def main():
    for p in (DB,TOKEN):
        try:p.unlink()
        except:pass
    ap,tp=port(),port(); srv=ThreadingHTTPServer(('127.0.0.1',tp),H); threading.Thread(target=srv.serve_forever,daemon=True).start(); env=os.environ.copy(); env.update({'DATABASE_URL':'sqlite:///./smoke.db','NEXVARY_ADMIN_PASSWORD':'ChangeMe123!','VSCAN_ALLOW_PRIVATE_TEST_TARGETS':'1','VSCAN_REQUEST_DELAY':'0'}); proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(ap)],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); base=f'http://127.0.0.1:{ap}'
    try:
        for _ in range(80):
            try:
                if json.loads(urllib.request.urlopen(base+'/health',timeout=1).read())['version']==VERSION: break
            except: time.sleep(.25)
        jar=http.cookiejar.CookieJar(); o=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)); post(o,base+'/login',{'username':'admin','password':'ChangeMe123!'}).read(); post(o,base+'/targets',{'name':'QA','url':f'http://127.0.0.1:{tp}','owner':'NEXVARY'}).read(); tid,tok=one('select id,verification_token from targets order by id desc limit 1'); TOKEN.write_text(tok); post(o,base+f'/targets/{tid}/verify',{}).read(); post(o,base+f'/targets/{tid}/request-scan',{}).read(); sid=one('select id from scan_requests order by id desc limit 1')[0]; post(o,base+f'/admin/scans/{sid}/approve',{'note':'QA'}).read(); post(o,base+f'/admin/scans/{sid}/run',{}).read(); status,score,pages,reqs=one(f'select status,security_score,pages_crawled,requests_made from scan_requests where id={sid}'); findings=one(f'select count(*) from findings where scan_request_id={sid}')[0]; surface=one(f'select count(*) from surface_items where scan_request_id={sid}')[0]; assert status=='completed' and pages>=2 and reqs>=2 and findings>=4 and surface>=4; print(f'LIVE E2E PASSED score={score} pages={pages} requests={reqs} findings={findings} surface={surface}')
    finally:
        srv.shutdown(); proc.terminate(); proc.wait(timeout=5)
        for p in (DB,TOKEN):
            try:p.unlink()
            except:pass
if __name__=='__main__': main()
