
import hashlib, secrets, sqlite3
from pathlib import Path
from fastapi import Header, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
FRONTEND = ROOT / "frontend"
SESSIONS: dict[str, str] = {}

def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn

def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()

def ensure_users(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("admin", sha("123456"), "管理员"))
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", sha("view123"), "只读"))

class LoginIn(BaseModel):
    username: str
    password: str

def require_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    u = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "登录已失效")
    return u

def _audit(conn, actor: str, action: str, detail: str):
    conn.execute(
        "INSERT INTO audit_log(actor,action,detail,created_at) VALUES (?,?,?,?)",
        (actor, action, detail, datetime.now().isoformat(timespec="seconds")),
    )

def current_role(conn, username: str) -> str:
    row = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    return row["role"] if row else ""

def require_write(authorization: str | None, *allowed_roles: str) -> str:
    """端点级兜底：令牌 -> 用户 -> 库内实时角色。

    主闸在 write_gate 中间件（负责留审计痕）；此处防端点被单测/未来路由绕过时仍拒写。
    """
    username = require_user(authorization)
    with connect() as conn:
        role = current_role(conn, username)
    if role not in allowed_roles:
        raise HTTPException(403, "只读席位无写权限")
    return username

from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

PRODUCT = "入站契约"
SKELETON = "Schema 契约版本约束入站校验，破坏性变更进缓冲或拒收，并与落库结果对账"

app = FastAPI(title=PRODUCT)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
READONLY_WRITE_ALLOW = {("POST", "/api/contract-requests")}  # 仅乙路径下只读可提交申请单
CONTRACT_WRITE_PREFIX = "/api/contracts"

@app.middleware("http")
async def write_gate(request, call_next):
    """写入口统一鉴权闸：只读令牌不得落笔，拦截在服务端生效并留审计痕。"""
    if request.method not in WRITE_METHODS or request.url.path == "/api/login":
        return await call_next(request)

    auth = request.headers.get("authorization")
    token = auth.removeprefix("Bearer ").strip() if auth and auth.startswith("Bearer ") else ""
    username = SESSIONS.get(token)
    if not username:
        return JSONResponse({"detail": "未登录"}, status_code=401)

    key = (request.method, request.url.path)
    with connect() as conn:
        role = current_role(conn, username)
        if role == "管理员":
            allowed = True
        else:
            path = intercept_path(conn)
            allowed = path == "乙" and key in READONLY_WRITE_ALLOW
            if not allowed:
                # 两边不得混用冒写支：甲路径下走乙的申请单、乙路径下直写正式契约，都算偏离拦截册
                mixes_branch = (path == "甲" and key in READONLY_WRITE_ALLOW) or \
                               (path == "乙" and request.url.path.startswith(CONTRACT_WRITE_PREFIX))
                if mixes_branch:
                    detail = f"冒写口径偏了：{username}({role}) 偏离冒写拦截册 {path} 路径支路，已拦下零写入"
                else:
                    detail = f"{username}({role}) 冒写被拦：零写入（当日拦截册 {path} 路径）"
                _audit(conn, username, "拦截", detail)
                conn.commit()

    if allowed:
        return await call_next(request)
    return JSONResponse({"detail": "只读席位无写权限"}, status_code=403)

def init_db():
    with connect() as conn:
        ensure_users(conn)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS contracts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          version TEXT UNIQUE NOT NULL,
          subject TEXT NOT NULL,
          mode TEXT NOT NULL,
          track TEXT NOT NULL,
          status TEXT NOT NULL,
          required_fields TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ingress_batches(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject TEXT NOT NULL,
          payload_fields TEXT NOT NULL,
          contract_version TEXT,
          result TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS buffers(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          batch_id INTEGER NOT NULL,
          reason TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contract_requests(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject TEXT NOT NULL,
          version TEXT NOT NULL,
          mode TEXT NOT NULL,
          required_fields TEXT NOT NULL,
          status TEXT NOT NULL,
          requested_by TEXT NOT NULL,
          approved_by TEXT,
          created_at TEXT NOT NULL,
          decided_at TEXT
        );
        CREATE TABLE IF NOT EXISTS intercept_policy(
          day TEXT PRIMARY KEY,
          chosen_path TEXT NOT NULL,
          chosen_by TEXT NOT NULL,
          chosen_at TEXT NOT NULL
        );
        """)
        if conn.execute("SELECT COUNT(*) c FROM contracts").fetchone()["c"] == 0:
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v3","订单入站","严格","正式","启用","order_id,amount,currency"))
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v4-shadow","订单入站","兼容","影子","试跑","order_id,amount,currency,channel"))
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v2","库存入站","严格","正式","停用","sku,qty"))

@app.on_event("startup")
def _s():
    init_db()

@app.get("/api/health")
def health():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) c FROM contracts").fetchone()["c"]
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON, "contracts": n, "db": str(DB_PATH)}

@app.post("/api/login")
def login(body: LoginIn):
    with connect() as c:
        row = c.execute("SELECT username,role FROM users WHERE username=? AND password_sha=?", (body.username, sha(body.password))).fetchone()
    if not row: raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16); SESSIONS[tok]=row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}

@app.get("/api/contracts")
def contracts(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items":[dict(r) for r in c.execute("SELECT * FROM contracts ORDER BY id").fetchall()]}

class PublishIn(BaseModel):
    subject: str
    version: str
    mode: str = "严格"
    track: str = "正式"
    required_fields: str

DEFAULT_INTERCEPT_PATH = "乙"

def today_policy(conn):
    return conn.execute("SELECT * FROM intercept_policy WHERE day=?",
                        (datetime.now().date().isoformat(),)).fetchone()

def intercept_path(conn) -> str:
    """当日拦截口径：已选定则锁定；未选定按默认乙（只读走申请单，不直写正式指针）。"""
    row = today_policy(conn)
    return row["chosen_path"] if row else DEFAULT_INTERCEPT_PATH

@app.post("/api/contracts/publish")
def publish_direct(body: PublishIn, authorization: str | None = Header(default=None)):
    """正式指针直写入口：管理员可调用；只读令牌在写入口闸被拦下零写入。

    鉴权在服务端生效，页面藏钮不算数。
    """
    username = require_write(authorization, "管理员")
    if body.track != "正式":
        raise HTTPException(400, "发布入口只写正式轨")
    with connect() as c:
        c.execute("UPDATE contracts SET status='停用' WHERE subject=? AND track='正式' AND status='启用'", (body.subject,))
        c.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                  (body.version, body.subject, body.mode, body.track, "启用", body.required_fields))
        _audit(c, username, "发布", f"管理员发布正式契约 {body.version}（{body.subject}）")
        return {"ok": True, "version": body.version, "published_by": username}

class ContractRequestIn(BaseModel):
    subject: str
    version: str
    mode: str = "严格"
    required_fields: str

@app.post("/api/contract-requests")
def submit_request(body: ContractRequestIn, authorization: str | None = Header(default=None)):
    """乾张乙路径：只读可提交申请单，但不得直接改正式指针。

    甲路径下只读提交申请单属偏离拦截册（由写入口闸拦截并记口径偏了）；此处兜底再核一次。
    """
    username = require_user(authorization)
    with connect() as c:
        role = current_role(c, username)
        if role != "管理员" and intercept_path(c) != "乙":
            _audit(c, username, "拦截", f"冒写口径偏了：{username}({role}) 偏离冒写拦截册 甲 路径支路（走乙的申请单），已拦下零写入")
            c.commit()
            raise HTTPException(403, "当日拦截口径下非管理员不得提交申请单")
        cur = c.execute(
            "INSERT INTO contract_requests(subject,version,mode,required_fields,status,requested_by,created_at) VALUES (?,?,?,?,?,?,?)",
            (body.subject, body.version, body.mode, body.required_fields, "待审批", username,
             datetime.now().isoformat(timespec="seconds")))
        _audit(c, username, "申请", f"{username}({role}) 提交正式指针申请单 #{cur.lastrowid} {body.version}")
        c.commit()
        return {"id": cur.lastrowid, "status": "待审批"}

@app.post("/api/contract-requests/{rid}/approve")
def approve_request(rid: int, authorization: str | None = Header(default=None)):
    """审批后由服务端写正式指针；同一申请并发抢批排队，后到只记审批争用。"""
    username = require_user(authorization)
    now = datetime.now().isoformat(timespec="seconds")
    with connect() as c:
        if current_role(c, username) != "管理员":
            _audit(c, username, "拦截", f"{username} 非管理员审批申请单 #{rid}，已拦下零写入")
            c.commit()
            raise HTTPException(403, "只读席位无审批权限")
        row = c.execute("SELECT * FROM contract_requests WHERE id=?", (rid,)).fetchone()
        if not row:
            raise HTTPException(404, "申请单不存在")
        # 条件更新抢占：只有把 待审批 -> 已通过 的那一个能继续写指针，其余记争用
        cur = c.execute(
            "UPDATE contract_requests SET status='已通过', approved_by=?, decided_at=? WHERE id=? AND status='待审批'",
            (username, now, rid))
        if cur.rowcount != 1:
            c.rollback()
            done = c.execute("SELECT approved_by FROM contract_requests WHERE id=?", (rid,)).fetchone()
            winner = done["approved_by"] if done and done["approved_by"] else "另一值班"
            _audit(c, username, "审批争用",
                   f"申请单 #{rid} 已被 {winner} 审批，{username} 后到争用，未重复写入")
            c.commit()
            raise HTTPException(409, "审批争用：该申请单已定")
        c.execute("UPDATE contracts SET status='停用' WHERE subject=? AND track='正式' AND status='启用'", (row["subject"],))
        c.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                  (row["version"], row["subject"], row["mode"], "正式", "启用", row["required_fields"]))
        _audit(c, username, "审批", f"管理员 {username} 审批申请单 #{rid} {row['version']}，由服务端写正式指针")
        c.commit()
        return {"ok": True, "id": rid, "version": row["version"], "approved_by": username}

@app.get("/api/audit")
def audit_trail(authorization: str | None = Header(default=None)):
    """审计条：只读可读，拦截痕在此可见。"""
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC").fetchall()]}

@app.get("/api/intercept/policy")
def get_intercept_policy(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        row = today_policy(c)
    if not row:
        # 当日未选定：按默认乙口径
        return {"chosen_path": DEFAULT_INTERCEPT_PATH, "chosen_on": "", "chosen_by": "", "chosen_at": "",
                "decided_today": False}
    return {"chosen_path": row["chosen_path"], "chosen_on": row["day"],
            "chosen_by": row["chosen_by"], "chosen_at": row["chosen_at"],
            "decided_today": True}

@app.post("/api/intercept/policy")
def set_intercept_policy(body: dict, authorization: str | None = Header(default=None)):
    """乾张选定后写入冒写拦截册，当天不许再换；偏离则拦下并记冒写口径偏了。"""
    username = require_write(authorization, "管理员")
    chosen = body.get("chosen_path")
    if chosen not in ("甲", "乙"):
        raise HTTPException(400, "路径仅限 甲 或 乙")
    today = datetime.now().date().isoformat()
    with connect() as c:
        row = today_policy(c)
        if row:
            if row["chosen_path"] != chosen:
                _audit(c, username, "拦截", f"冒写口径偏了：当日已选定 乾张{row['chosen_path']} 路径，拒绝改为{chosen}")
                c.commit()
                raise HTTPException(409, "当日拦截口径不可更换")
            return {"ok": True, "chosen_path": row["chosen_path"]}
        c.execute("INSERT INTO intercept_policy(day,chosen_path,chosen_by,chosen_at) VALUES (?,?,?,?)",
                  (today, chosen, username, datetime.now().isoformat(timespec="seconds")))
        _audit(c, username, "拦截册", f"乾张选定拦截口径为{chosen}")
        return {"ok": True, "chosen_path": chosen}

class IngressIn(BaseModel):
    subject: str
    payload_fields: str  # comma fields present

@app.post("/api/ingress/validate")
def validate(body: IngressIn, authorization: str | None = Header(default=None)):
    require_write(authorization, "管理员")
    fields = {x.strip() for x in body.payload_fields.split(",") if x.strip()}
    with connect() as c:
        ctr = c.execute("SELECT * FROM contracts WHERE subject=? AND track='正式' AND status='启用' ORDER BY id DESC LIMIT 1", (body.subject,)).fetchone()
        if not ctr:
            raise HTTPException(404, "无启用正式契约")
        need = {x.strip() for x in ctr["required_fields"].split(",") if x.strip()}
        missing = sorted(need - fields)
        now = datetime.now().isoformat(timespec="seconds")
        if missing:
            if ctr["mode"] == "兼容":
                cur = c.execute("INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at) VALUES (?,?,?,?,?,?)",
                                (body.subject, body.payload_fields, ctr["version"], "缓冲", "缺字段:"+ ",".join(missing), now))
                c.execute("INSERT INTO buffers(batch_id,reason) VALUES (?,?)", (cur.lastrowid, "缺字段进双写缓冲"))
                return {"result":"缓冲", "version": ctr["version"], "missing": missing, "batch_id": cur.lastrowid}
            cur = c.execute("INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at) VALUES (?,?,?,?,?,?)",
                            (body.subject, body.payload_fields, ctr["version"], "拒收", "缺字段:"+ ",".join(missing), now))
            return {"result":"拒收", "version": ctr["version"], "missing": missing, "batch_id": cur.lastrowid}
        cur = c.execute("INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at) VALUES (?,?,?,?,?,?)",
                        (body.subject, body.payload_fields, ctr["version"], "通过", "字段齐全", now))
        return {"result":"通过", "version": ctr["version"], "batch_id": cur.lastrowid}

@app.get("/api/ingress")
def ingress(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items":[dict(r) for r in c.execute("SELECT * FROM ingress_batches ORDER BY id DESC").fetchall()]}

@app.get("/api/buffers")
def buffers(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT b.*, i.subject, i.payload_fields FROM buffers b JOIN ingress_batches i ON i.id=b.batch_id ORDER BY b.id DESC""").fetchall()
        return {"items":[dict(r) for r in rows]}

@app.get("/api/reconcile")
def reconcile(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        total = c.execute("SELECT COUNT(*) c FROM ingress_batches").fetchone()["c"]
        passed = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='通过'").fetchone()["c"]
        buffered = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='缓冲'").fetchone()["c"]
        rejected = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='拒收'").fetchone()["c"]
        buf_rows = c.execute("SELECT COUNT(*) c FROM buffers").fetchone()["c"]
    return {"ingress_total": total, "passed": passed, "buffered": buffered, "rejected": rejected, "buffer_rows": buf_rows, "aligned": buffered == buf_rows}

@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")
app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
