import os, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("NEXVARY_ADMIN_PASSWORD","ChangeMe123!")
from fastapi.testclient import TestClient
from app.main import app
from app.scanner import SurfaceParser, calculate_score
from app.models import Finding
from app.security import hash_password, verify_password, normalize_target, same_scope
from app.intelligence import fingerprint_technologies, extract_js_routes, source_map_hint, secret_indicators, mixed_content_urls

client=TestClient(app)

def test_health():
    r=client.get('/health'); assert r.status_code==200 and r.json()['version']=='1.2.5'

def test_password_hash_roundtrip():
    h=hash_password('secret'); assert verify_password('secret',h) and not verify_password('wrong',h)

def test_dashboard_requires_login():
    r=client.get('/',follow_redirects=False); assert r.status_code==303 and r.headers['location']=='/login'

def test_admin_login():
    r=client.post('/login',data={'username':'admin','password':'ChangeMe123!'},follow_redirects=False); assert r.status_code==303

def test_target_normalization_and_scope():
    assert normalize_target('example.com')=='https://example.com'; assert same_scope('https://example.com/a','example.com'); assert not same_scope('https://sub.example.com/a','example.com')

def test_surface_parser():
    p=SurfaceParser('https://example.com/account'); p.feed('<a href="/api/u?id=7">U</a><script src="/app.js"></script><form method="post" action="/login"><input name="email"><input type="password" name="password"></form>'); assert 'https://example.com/api/u?id=7' in p.links and p.scripts[0]=='https://example.com/app.js' and p.forms[0]['method']=='POST' and p.forms[0]['inputs'][1]['type']=='password'

def test_score_ignores_potential_and_deduplicates():
    fs=[Finding(severity='Medium',title='HSTS header missing',detail='',remediation='',endpoint='https://a'),Finding(severity='Medium',title='HSTS header missing',detail='',remediation='',endpoint='https://b'),Finding(severity='High',title='Potential',detail='',remediation='',endpoint='https://a',confirmed=False)]; assert calculate_score(fs)==92

def test_dashboard_flash_render():
    with TestClient(app) as c:
        c.post('/login',data={'username':'admin','password':'ChangeMe123!'}); r=c.get('/?notice=Verified&error=Retry'); assert 'Verified' in r.text and 'Retry' in r.text

def test_passive_technology_fingerprint():
    found=dict(fingerprint_technologies({'server':'nginx'},'<html><script src="/_next/static/chunks/app.js"></script></html>',['https://example.com/jquery-3.7.1.min.js']))
    assert 'nginx' in found and 'Next.js' in found and 'jQuery' in found

def test_js_route_intelligence_is_same_source_only():
    text='fetch("/api/v2/users"); axios.post("/graphql"); const x="/oauth/token";'
    routes=extract_js_routes('https://example.com/static/app.js',text)
    assert 'https://example.com/api/v2/users' in routes and 'https://example.com/graphql' in routes

def test_source_map_hint():
    assert source_map_hint('https://example.com/app.js','console.log(1);\n//# sourceMappingURL=app.js.map')=='https://example.com/app.js.map'

def test_secret_indicators_redact_values():
    hits=secret_indicators('const apiKey="1234567890abcdef1234567890abcdef";')
    assert hits and '1234567890abcdef1234567890abcdef' not in hits[0][1]

def test_mixed_content_detection():
    urls=mixed_content_urls('https://example.com','<script src="http://cdn.example.net/a.js"></script>')
    assert urls==['http://cdn.example.net/a.js']
