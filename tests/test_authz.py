"""令牌冒写拦截验收：只覆盖令牌拦截与审批后服务端写。

覆盖点：
1. 只读令牌调用正式契约写入口 -> 无权限、正式指针零写入、审计条留拦截痕
2. 管理员直写正式契约 -> 放行
3. 只读提交申请单 -> 不改正式指针；只读审批 -> 无权限；管理员审批 -> 服务端写
4. 同一申请单两名值班并发审批 -> 排队，后到只记"审批争用"，正式版本只落一次
5. 只读令牌调用其它写入口（入站校验）-> 无权限零写入
6. 冒写拦截册当日选定路径不可更换
"""

import threading

import pytest
from fastapi.testclient import TestClient

from app import app as application, init_db

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB_PATH", tmp_path / "t.db")
    init_db()
    yield


@pytest.fixture
def client():
    return TestClient(application)


def _tok(c, username, password):
    r = c.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def _contracts(c, tok):
    r = c.get("/api/contracts", headers=_h(tok))
    assert r.status_code == 200
    return r.json()["items"]


def _enabled_formal(c, tok):
    return [x for x in _contracts(c, tok) if x["track"] == "正式" and x["status"] == "启用"]


def _audit(c, tok):
    r = c.get("/api/audit", headers=_h(tok))
    assert r.status_code == 200
    return r.json()["items"]


def test_viewer_token_publish_denied_and_zero_write(client):
    a = _tok(client, "admin", "123456")
    v = _tok(client, "viewer", "view123")
    _choose_path(client, a, "乙")
    before = _contracts(client, v)
    r = client.post(
        "/api/contracts/publish",
        headers=_h(v),
        json={"subject": "订单入站", "version": "v9-rogue", "mode": "严格",
              "required_fields": "order_id"},
    )
    assert r.status_code == 403, r.text
    assert _contracts(client, v) == before
    assert not any(x["version"] == "v9-rogue" for x in _contracts(client, v))
    hits = [a2 for a2 in _audit(client, v) if a2["action"] == "拦截"]
    assert hits and any("冒写口径偏了" in a2["detail"] and "零写入" in a2["detail"] for a2 in hits)


def test_viewer_publish_denied_under_jia_path(client):
    a = _tok(client, "admin", "123456")
    v = _tok(client, "viewer", "view123")
    _choose_path(client, a, "甲")
    before = _contracts(client, v)
    r = client.post(
        "/api/contracts/publish",
        headers=_h(v),
        json={"subject": "订单入站", "version": "v9-rogue", "mode": "严格",
              "required_fields": "order_id"},
    )
    assert r.status_code == 403, r.text
    assert _contracts(client, v) == before
    hits = [x for x in _audit(client, v) if x["action"] == "拦截"]
    assert hits and any("零写入" in x["detail"] for x in hits)


def test_admin_publish_still_works(client):
    a = _tok(client, "admin", "123456")
    r = client.post(
        "/api/contracts/publish",
        headers=_h(a),
        json={"subject": "订单入站", "version": "v10", "mode": "严格",
              "required_fields": "order_id,amount,currency"},
    )
    assert r.status_code == 200, r.text
    enabled = _enabled_formal(client, a)
    assert [x["version"] for x in enabled] == ["v10"]


def _choose_path(c, tok, path):
    r = c.post("/api/intercept/policy", headers=_h(tok), json={"chosen_path": path})
    assert r.status_code == 200, r.text


def test_request_then_approval_writes_server_side(client):
    v = _tok(client, "viewer", "view123")
    a = _tok(client, "admin", "123456")
    _choose_path(client, a, "乙")
    r = client.post(
        "/api/contract-requests",
        headers=_h(v),
        json={"subject": "订单入站", "version": "v11", "mode": "严格",
              "required_fields": "order_id,amount,currency"},
    )
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    assert r.json()["status"] == "待审批"
    # 申请阶段正式指针不动
    assert not any(x["version"] == "v11" for x in _contracts(client, v))
    # 只读不能审批
    assert client.post(f"/api/contract-requests/{rid}/approve", headers=_h(v)).status_code == 403
    assert not any(x["version"] == "v11" for x in _contracts(client, v))
    # 管理员审批后由服务端写正式指针
    r = client.post(f"/api/contract-requests/{rid}/approve", headers=_h(a))
    assert r.status_code == 200, r.text
    enabled = _enabled_formal(client, a)
    assert [x["version"] for x in enabled] == ["v11"]
    assert any("审批" in x["action"] for x in _audit(client, a))


def test_same_request_concurrent_approval_records_contention(client):
    v = _tok(client, "viewer", "view123")
    a = _tok(client, "admin", "123456")
    _choose_path(client, a, "乙")
    rid = client.post(
        "/api/contract-requests",
        headers=_h(v),
        json={"subject": "订单入站", "version": "v12", "mode": "严格",
              "required_fields": "order_id,amount,currency"},
    ).json()["id"]

    barrier = threading.Barrier(2)
    results = []

    def approve():
        c2 = TestClient(application)
        barrier.wait(timeout=5)
        r = c2.post(f"/api/contract-requests/{rid}/approve", headers=_h(a))
        results.append(r.status_code)

    threads = [threading.Thread(target=approve) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert sorted(results) == [200, 409], results
    hits = [x for x in _audit(client, a) if x["action"] == "审批争用"]
    assert hits, "后到的审批必须记审批争用"
    rows = [x for x in _contracts(client, a) if x["version"] == "v12"]
    assert len(rows) == 1 and rows[0]["status"] == "启用"


def test_viewer_cannot_write_ingress(client):
    v = _tok(client, "viewer", "view123")
    before = client.get("/api/ingress", headers=_h(v)).json()["items"]
    r = client.post(
        "/api/ingress/validate",
        headers=_h(v),
        json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"},
    )
    assert r.status_code == 403, r.text
    after = client.get("/api/ingress", headers=_h(v)).json()["items"]
    assert after == before


def test_intercept_ledger_path_locked_for_today(client):
    a = _tok(client, "admin", "123456")
    v = _tok(client, "viewer", "view123")
    # 未选定前按默认乙口径：只读可提交申请单
    r = client.post("/api/contract-requests", headers=_h(v),
                    json={"subject": "订单入站", "version": "v13", "required_fields": "order_id"})
    assert r.status_code == 200, r.text
    # 选定甲后当天锁定，不得再换
    _choose_path(client, a, "甲")
    p = client.get("/api/intercept/policy", headers=_h(a)).json()
    assert p["chosen_path"] == "甲" and p["decided_today"] is True
    assert p["chosen_on"]
    r = client.post("/api/intercept/policy", headers=_h(a), json={"chosen_path": "乙"})
    assert r.status_code == 409, r.text
    assert client.get("/api/intercept/policy", headers=_h(a)).json()["chosen_path"] == "甲"
    hits = [x for x in _audit(client, a) if x["action"] == "拦截"]
    assert any("冒写口径偏了" in x["detail"] for x in hits)
    # 甲口径下只读提交申请单（乙支）被拦
    r = client.post("/api/contract-requests", headers=_h(v),
                    json={"subject": "订单入站", "version": "v14", "required_fields": "order_id"})
    assert r.status_code == 403, r.text
