import os, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("NEXVARY_ADMIN_PASSWORD","ChangeMe123!")
from fastapi.testclient import TestClient
from app.main import app
from app.scanner import SurfaceParser, calculate_score
from app.models import Finding
from app.security import hash_password, verify_password, normalize_target, same_scope

client=TestClient(app)
def test_health():
    r=client.get('/health'); assert r.status_code==200 and r.json()['version']=='0.5.0'
def test_password_hash_roundtrip():
    h=hash_password('secret'); assert verify_password('secret',h) and not verify_password('wrong',h)
def test_dashboard_requires_login():
    r=client.get('/',follow_redirects=False); assert r.status_code==303 and r.headers['location']=='/login'
def test_admin_login():
    r=client.post('/login',data={'username':'admin','password':'ChangeMe123!'},follow_redirects=False); assert r.status_code==303
def test_target_normalization_and_scope():
    assert normalize_target('example.com')=='https://example.com'; assert same_scope('https://example.com/a','example.com'); assert not same_scope('https://sub.example.com/a','example.com')
def test_surface_parser():
    p=SurfaceParser('https://example.com/account'); p.feed('<a href="/api/u?id=7">U</a><script src="/app.js"></script><form method="post" action="/login"><input name="email"><input type="password" name="password"></form>'); assert 'https://example.com/api/u?id=7' in p.links and p.scripts[0]=='https://example.com/app.js' and p.forms[0]['method']=='POST'
def test_score_ignores_potential_and_deduplicates():
    fs=[Finding(severity='Medium',title='HSTS header missing',detail='',remediation='',endpoint='https://a'),Finding(severity='Medium',title='HSTS header missing',detail='',remediation='',endpoint='https://b'),Finding(severity='High',title='Potential',detail='',remediation='',endpoint='https://a',confirmed=False)]; assert calculate_score(fs)==92
def test_dashboard_flash_render():
    with TestClient(app) as c:
        c.post('/login',data={'username':'admin','password':'ChangeMe123!'}); r=c.get('/?notice=Verified&error=Retry'); assert 'Verified' in r.text and 'Retry' in r.text
