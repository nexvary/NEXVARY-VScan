import os, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("NEXVARY_ADMIN_PASSWORD","ChangeMe123!")
from fastapi.testclient import TestClient
from app.main import app
from app.scanner import SurfaceParser, calculate_score
from app.models import Finding
from app.security import hash_password, verify_password, normalize_target, same_scope
from app.intelligence import (
    browser_isolation_headers, extract_asset_versions, extract_js_routes,
    fingerprint_technologies, mixed_content_urls, parse_security_txt,
    secret_indicators, source_map_hint, third_party_hosts,
)

client=TestClient(app)

def test_health():
    r=client.get('/health'); assert r.status_code==200 and r.json()['version']=='0.9.5'

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

def test_surface_parser_tracks_sri_metadata():
    p=SurfaceParser('https://example.com/'); p.feed('<script src="https://cdn.example.net/jquery-3.7.1.min.js" integrity="sha384-demo"></script><link rel="stylesheet" href="https://cdn.example.net/bootstrap-5.3.3.min.css">')
    assert p.script_meta[0]['integrity']=='sha384-demo' and p.style_meta[0]['integrity']==''

def test_score_ignores_potential_and_deduplicates():
    fs=[Finding(severity='Medium',title='HSTS header missing',detail='',remediation='',endpoint='https://a'),Finding(severity='Medium',title='HSTS header missing',detail='',remediation='',endpoint='https://b'),Finding(severity='High',title='Potential',detail='',remediation='',endpoint='https://a',confirmed=False)]; assert calculate_score(fs)==92

def test_dashboard_flash_render():
    with TestClient(app) as c:
        c.post('/login',data={'username':'admin','password':'ChangeMe123!'}); r=c.get('/?notice=Verified&error=Retry'); assert 'Verified' in r.text and 'Retry' in r.text

def test_passive_technology_fingerprint():
    found=dict(fingerprint_technologies({'server':'nginx'},'<html><script src="/_next/static/chunks/app.js"></script></html>',['https://example.com/jquery-3.7.1.min.js']))
    assert 'nginx' in found and 'Next.js' in found and 'jQuery' in found

def test_asset_version_intelligence():
    hits=extract_asset_versions('<meta name="generator" content="WordPress 6.6.2">',['https://cdn.example.net/jquery-3.7.1.min.js','https://example.com/bootstrap-5.3.3.min.css'])
    assert ('WordPress','6.6.2','generator') in hits
    assert any(x[0]=='jQuery' and x[1]=='3.7.1' for x in hits)
    assert any(x[0]=='Bootstrap' and x[1]=='5.3.3' for x in hits)

def test_third_party_inventory_does_not_require_fetching():
    hosts=third_party_hosts('https://example.com/a',['https://example.com/app.js','https://cdn.example.net/lib.js','https://fonts.example.org/x.css'])
    assert hosts==['cdn.example.net','fonts.example.org']

def test_security_txt_parser():
    fields=dict(parse_security_txt('Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: en, ar\nUnknown: ignore'))
    assert fields['contact']=='mailto:security@example.com' and 'unknown' not in fields

def test_browser_isolation_headers():
    data=browser_isolation_headers({'cross-origin-opener-policy':'same-origin','server':'nginx'})
    assert data=={'cross-origin-opener-policy':'same-origin'}

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
