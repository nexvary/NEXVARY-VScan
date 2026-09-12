from types import SimpleNamespace
import pytest
from app.portfolio_intelligence import portfolio_summary, score_band
from app.release_guard import release_guard, assert_production_ready


def test_portfolio_summary_uses_latest_completed_scan_per_target():
    targets=[SimpleNamespace(id=1,verified=True),SimpleNamespace(id=2,verified=False)]
    scans=[
        SimpleNamespace(id=1,target_id=1,status='completed',security_score=70),
        SimpleNamespace(id=2,target_id=1,status='completed',security_score=90),
        SimpleNamespace(id=3,target_id=2,status='pending',security_score=None),
    ]
    s=portfolio_summary(targets,scans)
    assert s['targets_total']==2
    assert s['targets_verified']==1
    assert s['verification_rate']==50
    assert s['average_completed_score']==80
    assert s['current_portfolio_score']==90
    assert s['targets_with_baseline']==1


def test_score_bands():
    assert score_band(95)=='strong'
    assert score_band(80)=='managed'
    assert score_band(65)=='needs-attention'
    assert score_band(45)=='high-priority'
    assert score_band(None)=='unknown'


def test_release_guard_warns_in_development_but_blocks_in_production():
    dev=release_guard(production_mode=False,admin_password='ChangeMe123!',session_secret='short',secure_cookies=False)
    assert dev['status']=='development-warning' and not dev['ready']
    prod=release_guard(production_mode=True,admin_password='ChangeMe123!',session_secret='short',secure_cookies=False)
    assert prod['status']=='blocked'
    with pytest.raises(RuntimeError):
        assert_production_ready(prod)


def test_release_guard_accepts_hardened_production():
    status=release_guard(production_mode=True,admin_password='A-unique-admin-secret-value',session_secret='x'*48,secure_cookies=True)
    assert status['ready'] and status['status']=='ready'
    assert_production_ready(status)
