# ═══════════════════════════════════════════════════════════════
# TOCXIC v78 — SUPERADMIN · DB SESSIONS · NO TIMEOUT · FULLY WORKING
# ═══════════════════════════════════════════════════════════════
import os
import re
import io
import json
import uuid
import hmac
import base64
import hashlib
import logging
import datetime
import secrets
import time
import urllib.request
import urllib.parse
import traceback
import zipfile
import tempfile
import shutil
from functools import wraps
from threading import Lock
from datetime import datetime as _dt, timezone, timedelta

from bson import ObjectId, Binary
from gridfs import GridFSBucket
from flask import (
    Flask, request, jsonify, render_template_string, send_file,
    redirect, abort, send_from_directory, after_this_request,
)
from flask_cors import CORS
from pymongo import MongoClient, InsertOne, UpdateOne, UpdateMany, DeleteOne, DeleteMany, ReplaceOne
from pymongo.errors import (
    OperationFailure, ServerSelectionTimeoutError, ConfigurationError,
)
from dotenv import load_dotenv

load_dotenv()

# ═══════════════════════════════════════════════
# APP BOOTSTRAP
# ═══════════════════════════════════════════════
app = Flask(__name__)
CORS(app, supports_credentials=True)
try:
    app.json.sort_keys = False
except Exception:
    try:
        app.config['JSON_SORT_KEYS'] = False
    except Exception:
        pass
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════
MASTER_CLUSTER_URI = os.getenv(
    'MASTER_DB_URI',
    'mongodb+srv://apimanager_db_user:xWae4pyKMZIKOAp3@mongosever.yeaf5o8.mongodb.net/?retryWrites=true&w=majority'
)

DB_USER_URIS     = os.getenv('DB_USER_URIS',     'tocxic_user_uris')
DB_GMASTER       = os.getenv('DB_GMASTER',       'tocxic_gmaster')
DB_VISITORS      = os.getenv('DB_VISITORS',      'tocxic_visitors')
DB_FINGERPRINTS  = os.getenv('DB_FINGERPRINTS',  'tocxic_fingerprints')

MASTER_EMAIL = os.getenv('MASTER_EMAIL', 'admin')
MASTER_PASS  = os.getenv('MASTER_PASS',  'admin')

GM_USER = os.getenv('GRANDMASTER_USER', 'admin')
GM_PASS = os.getenv('GRANDMASTER_PASS', 'admin')
GM_BYPASS_KEY = (
    os.getenv('GM_BYPASS_KEY') or
    os.getenv('GRANDMASTER_BYPASS_KEY') or
    'TOCXIC-GM-6767-SOVEREIGN-VOID-X9K4-BYPASS'
)

ADMIN_PATH = 'superadmin'

OWNER_ADMIN_DB   = os.getenv('OWNER_ADMIN_DB', 'tocxic_owner')
OWNER_USER_DEF   = os.getenv('OWNER_USER', 'admin')
OWNER_PASS_DEF   = os.getenv('OWNER_PASS', 'admin')
OWNER_PATH       = 'superadmin/owner'
OWNER_PANEL_PATH = 'superadmin/owner-panel'

IP_INFO_API = "https://ip-information-omega.vercel.app/api/ip?ip="
PINCODE_API = "https://postmaster-steel.vercel.app/api/pincode?code="

CONNECT_TIMEOUT_MS  = 8000
SERVER_SELECTION_MS = 8000
SOCKET_TIMEOUT_MS   = 30000

MASTER_CLIENT = None

IST = timezone(timedelta(hours=5, minutes=30))

logger.info("═" * 60)
logger.info("🥭 TOCXIC v78 — /superadmin · DB sessions · no timeout")
logger.info("═" * 60)
logger.info(f"MASTER:  {MASTER_EMAIL} / {MASTER_PASS}")
logger.info(f"GM_USER: {GM_USER} / {GM_PASS}")
logger.info(f"ADMIN_PATH: /{ADMIN_PATH}")
logger.info(f"OWNER PANEL: /{OWNER_PANEL_PATH}")
logger.info("═" * 60)

# ═══════════════════════════════════════════════
# SECURITY HEADERS
# ═══════════════════════════════════════════════
@app.after_request
def _secure_headers(resp):
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    resp.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    resp.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive, nosnippet'
    return resp

# ═══════════════════════════════════════════════
# URI UTILITIES
# ═══════════════════════════════════════════════
def _validate_uri(uri):
    if not uri or not isinstance(uri, str): return "URI is empty"
    uri = uri.strip()
    if len(uri) > 2000: return "URI too long"
    if not (uri.startswith("mongodb://") or uri.startswith("mongodb+srv://")):
        return "URI must start with mongodb:// or mongodb+srv://"
    return None

def _is_srv_uri(uri): return uri.startswith("mongodb+srv://")

def _check_dnspython():
    try:
        import dns.resolver  # noqa
        return True, None
    except ImportError:
        return False, "dnspython missing"

def get_master_client():
    global MASTER_CLIENT
    if MASTER_CLIENT is not None:
        try:
            MASTER_CLIENT.admin.command('ping')
            return MASTER_CLIENT
        except Exception:
            MASTER_CLIENT = None
    if not MASTER_CLUSTER_URI: return None
    if _is_srv_uri(MASTER_CLUSTER_URI):
        ok, err = _check_dnspython()
        if not ok:
            logger.error(f"master dnspython: {err}"); return None
    try:
        MASTER_CLIENT = MongoClient(
            MASTER_CLUSTER_URI,
            serverSelectionTimeoutMS=SERVER_SELECTION_MS,
            connectTimeoutMS=CONNECT_TIMEOUT_MS,
            socketTimeoutMS=SOCKET_TIMEOUT_MS,
            retryWrites=True, maxPoolSize=100, minPoolSize=5,
        )
        MASTER_CLIENT.admin.command('ping')
        logger.info("✓ Master cluster connected")
        return MASTER_CLIENT
    except Exception as e:
        logger.error(f"master connect: {e}"); MASTER_CLIENT = None; return None

def get_client_uri(uri):
    err = _validate_uri(uri)
    if err: return None, err
    uri = uri.strip()
    if _is_srv_uri(uri):
        ok, derr = _check_dnspython()
        if not ok: return None, derr
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=SERVER_SELECTION_MS,
            connectTimeoutMS=CONNECT_TIMEOUT_MS, socketTimeoutMS=SOCKET_TIMEOUT_MS,
            retryWrites=True, maxPoolSize=50)
        client.admin.command('ping')
        return client, None
    except ConfigurationError as e: return None, f"Config: {e}"
    except ServerSelectionTimeoutError as e: return None, f"Timeout: {e}"
    except OperationFailure as e: return None, f"Auth: {e}"
    except Exception as e: return None, f"{type(e).__name__}: {e}"

def mask_uri(uri):
    try:
        if '://' not in uri: return uri
        protocol, rest = uri.split('://', 1)
        if '@' in rest:
            creds, host = rest.split('@', 1)
            if ':' in creds:
                u, p = creds.split(':', 1)
                return f"{protocol}://{u[:2]}•••:{'•' * min(len(p), 8)}@{host}"
            return f"{protocol}://•••@{host}"
        return uri
    except Exception: return uri

def _uri_hash(uri): return hashlib.sha256(uri.strip().encode()).hexdigest()[:32]
def _hash_device(ip, ua, device_id, fp):
    return hashlib.sha256(f"{ip}|{ua}|{device_id}|{fp}".encode()).hexdigest()[:32]

def _slugify(s):
    s = re.sub(r'[^a-zA-Z0-9\-\s]', '', s or '').strip().lower()
    return re.sub(r'\s+', '-', s)[:48] or 'org'

def _client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()

def _device_id(): return request.cookies.get('txc_device') or ''

# ═══════════════════════════════════════════════
# DB ROUTERS
# ═══════════════════════════════════════════════
def _db_user_uris():
    c = get_master_client(); return c[DB_USER_URIS] if c else None
def _db_gmaster():
    c = get_master_client(); return c[DB_GMASTER] if c else None
def _db_visitors():
    c = get_master_client(); return c[DB_VISITORS] if c else None
def _db_fingerprints():
    c = get_master_client(); return c[DB_FINGERPRINTS] if c else None
def _db_owner():
    c = get_master_client(); return c[OWNER_ADMIN_DB] if c else None

def _coll_uris():
    d = _db_user_uris(); return d['uris'] if d is not None else None
def _coll_audits():
    d = _db_gmaster(); return d['audits'] if d is not None else None
def _coll_logins():
    d = _db_gmaster(); return d['login_attempts'] if d is not None else None
def _coll_master_uris():
    d = _db_gmaster(); return d['master_uris'] if d is not None else None
def _coll_settings():
    d = _db_gmaster(); return d['settings'] if d is not None else None
def _coll_visits():
    d = _db_visitors(); return d['visits'] if d is not None else None
def _coll_visitor_sess():
    d = _db_visitors(); return d['sessions'] if d is not None else None
def _coll_devices():
    d = _db_fingerprints(); return d['devices'] if d is not None else None

# ═══════════════════════════════════════════════
# ENCRYPTION + TIME HELPERS (must be before DBSessions)
# ═══════════════════════════════════════════════
try:
    from cryptography.fernet import Fernet
    _k = base64.urlsafe_b64encode(hashlib.sha256(app.config['SECRET_KEY'].encode()).digest())
    _f = Fernet(_k)
    def enc(s): return _f.encrypt(s.encode()).decode()
    def dec(s): return _f.decrypt(s.encode()).decode()
except Exception:
    def enc(s): return base64.b64encode(s.encode()).decode()
    def dec(s): return base64.b64decode(s.encode()).decode()

def now_utc(): return _dt.now(timezone.utc)

def iso_utc(dt):
    if dt is None: return None
    if isinstance(dt, str): return dt
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    else: dt = dt.astimezone(timezone.utc)
    return dt.isoformat()

def safe_dec(v):
    try: return dec(v) if v else ""
    except Exception: return "(decrypt error)"

# ═══════════════════════════════════════════════════════════════
# DB-BACKED SESSIONS (survives multi-worker + redeploy)
# ═══════════════════════════════════════════════════════════════
class DBSessions:
    """Cross-worker session store — backed by MongoDB, cached in memory."""
    def __init__(self, cache_ttl=5):
        self._cache = {}
        self._cache_ttl = cache_ttl
        self._lock = Lock()

    def _coll(self):
        try:
            c = get_master_client()
            if c is None: return None
            return c[DB_GMASTER]['app_sessions']
        except Exception:
            return None

    def get(self, vid, default=None):
        if not vid: return default
        now = time.time()
        with self._lock:
            if vid in self._cache:
                val, ts = self._cache[vid]
                if now - ts < self._cache_ttl:
                    return dict(val)
        try:
            coll = self._coll()
            if coll is not None:
                doc = coll.find_one({"_id": vid})
                if doc:
                    doc.pop("_id", None)
                    doc.pop("_updated", None)
                    doc.pop("_created", None)
                    with self._lock:
                        self._cache[vid] = (dict(doc), now)
                    return dict(doc)
        except Exception as e:
            logger.error(f"session get: {e}")
        with self._lock:
            if vid in self._cache:
                return dict(self._cache[vid][0])
        return default

    def __getitem__(self, vid):
        v = self.get(vid)
        if v is None: raise KeyError(vid)
        return v

    def __setitem__(self, vid, value):
        if not vid or value is None: return
        d = dict(value)
        d["_id"] = vid
        d["_updated"] = now_utc()
        with self._lock:
            self._cache[vid] = (dict(d), time.time())
        try:
            coll = self._coll()
            if coll is not None:
                upd = dict(d)
                upd.pop("_id", None)
                coll.update_one(
                    {"_id": vid},
                    {"$set": upd, "$setOnInsert": {"_created": now_utc()}},
                    upsert=True
                )
        except Exception as e:
            logger.error(f"session set: {e}")

    def __contains__(self, vid):
        return self.get(vid) is not None

    def __delitem__(self, vid):
        try:
            coll = self._coll()
            if coll is not None: coll.delete_one({"_id": vid})
        except Exception: pass
        with self._lock:
            self._cache.pop(vid, None)

    def pop(self, vid, default=None):
        v = self.get(vid)
        if v is not None: self.__delitem__(vid)
        return v if v is not None else default

    def __len__(self):
        try:
            coll = self._coll()
            if coll is not None: return coll.count_documents({})
        except Exception: pass
        with self._lock:
            return len(self._cache)

SESSIONS = DBSessions()

# ═══════════════════════════════════════════════
# DYNAMIC CREDENTIALS
# ═══════════════════════════════════════════════
def _get_gm_creds():
    default = (GM_USER, GM_PASS, GM_BYPASS_KEY)
    try:
        d = _db_gmaster()
        if d is None: return default
        doc = d['settings'].find_one({'_id': 'gm_creds'})
        if not doc: return default
        return (
            doc.get('user') or default[0],
            doc.get('pass') or default[1],
            doc.get('bypass_key') or default[2],
        )
    except Exception as e:
        logger.error(f"get_gm_creds: {e}")
        return default

def _get_master_creds():
    default = (MASTER_EMAIL, MASTER_PASS)
    try:
        d = _db_gmaster()
        if d is None: return default
        doc = d['settings'].find_one({'_id': 'master_creds'})
        if not doc: return default
        return (
            doc.get('email') or default[0],
            doc.get('pass') or default[1],
        )
    except Exception as e:
        logger.error(f"get_master_creds: {e}")
        return default

def _set_gm_creds(user=None, pwd=None, bypass_key=None):
    d = _db_gmaster()
    if d is None: return False
    upd = {'updated_at': datetime.datetime.utcnow()}
    if user: upd['user'] = user
    if pwd: upd['pass'] = pwd
    if bypass_key: upd['bypass_key'] = bypass_key
    try:
        d['settings'].update_one({'_id': 'gm_creds'}, {'$set': upd}, upsert=True)
        return True
    except Exception as e:
        logger.error(f"set_gm_creds: {e}")
        return False

def _set_master_creds(email=None, pwd=None):
    d = _db_gmaster()
    if d is None: return False
    upd = {'updated_at': datetime.datetime.utcnow()}
    if email: upd['email'] = email
    if pwd: upd['pass'] = pwd
    try:
        d['settings'].update_one({'_id': 'master_creds'}, {'$set': upd}, upsert=True)
        return True
    except Exception as e:
        logger.error(f"set_master_creds: {e}")
        return False

# ═══════════════════════════════════════════════
# TRACKING + AUDIT
# ═══════════════════════════════════════════════
def track_visitor():
    try:
        visits = _coll_visits(); vsess = _coll_visitor_sess(); devices = _coll_devices()
        if visits is None and vsess is None and devices is None: return
        ip = _client_ip(); fp = request.headers.get('X-Fingerprint', 'unknown')
        did = _device_id(); ua = request.headers.get('User-Agent', '')
        now = datetime.datetime.utcnow()
        if visits is not None:
            visits.insert_one({
                'ip': ip, 'path': request.path, 'method': request.method,
                'ts': now, 'ua': ua, 'referrer': request.headers.get('Referer', ''),
                'device_id': did or None, 'fingerprint': fp,
            })
        if vsess is not None and did:
            vsess.update_one({'device_id': did},
                {'$set': {'last_seen': now, 'last_path': request.path, 'ip': ip},
                 '$setOnInsert': {'first_seen': now, 'page_count': 0},
                 '$inc': {'page_count': 1}}, upsert=True)
        if devices is not None:
            dhash = _hash_device(ip, ua, did or '', fp)
            devices.update_one({'device_hash': dhash},
                {'$set': {'last_seen': now, 'last_ip': ip, 'last_ua': ua,
                          'fingerprint': fp, 'cookies.device_id': did or None},
                 '$setOnInsert': {'first_seen': now, 'cookies': {'device_id': did or None},
                                  'browser': {}, 'vids': [], 'hits': 0},
                 '$inc': {'hits': 1}, '$addToSet': {'ips': ip}}, upsert=True)
    except Exception as e: logger.error(f"track_visitor: {e}")

def log_audit(action, user, details, ip=None):
    try:
        audits = _coll_audits()
        if audits is None: return
        ua = ''
        try: ua = request.headers.get('User-Agent', '')
        except Exception: pass
        audits.insert_one({
            'action': action, 'user': user, 'details': details,
            'ip': ip or _client_ip(), 'timestamp': datetime.datetime.utcnow(), 'ua': ua,
        })
    except Exception as e: logger.error(f"audit: {e}")

def log_login_attempt(success, identifier, role):
    try:
        logins = _coll_logins()
        if logins is None: return
        logins.insert_one({
            'identifier': identifier, 'role': role, 'success': success,
            'ip': _client_ip(), 'timestamp': datetime.datetime.utcnow(),
            'ua': request.headers.get('User-Agent', ''),
        })
    except Exception as e: logger.error(f"login: {e}")

# ═══════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════
def _get_session():
    vid = (request.headers.get('X-Session-ID')
           or request.cookies.get('vid')
           or request.args.get('vid'))
    if not vid: return None, None
    return vid, SESSIONS.get(vid)

def auth_required(f):
    @wraps(f)
    def deco(*a, **kw):
        track_visitor()
        _, sess = _get_session()
        if not sess: return jsonify({'error': 'Unauthorized'}), 401
        return f(*a, **kw)
    return deco

def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapped(*a, **kw):
            track_visitor()
            _, sess = _get_session()
            if not sess: return jsonify({'error': 'Unauthorized'}), 401
            if sess.get('role') not in roles: return jsonify({'error': 'Forbidden'}), 403
            return f(*a, **kw)
        return wrapped
    return deco

def to_json(obj, depth=0):
    if depth > 12: return None
    try:
        if obj is None: return None
        if isinstance(obj, ObjectId): return str(obj)
        if isinstance(obj, datetime.datetime): return obj.isoformat()
        if isinstance(obj, (bool, int, float)): return obj
        if isinstance(obj, str): return obj[:100000]
        if isinstance(obj, bytes): return obj.decode('utf-8', errors='ignore')[:5000]
        if isinstance(obj, Binary): return f"<Binary:{len(obj)} bytes>"
        if isinstance(obj, dict):
            if len(obj) > 5000: return {'_error': 'too large'}
            return {k: to_json(v, depth + 1) for k, v in list(obj.items())[:1000]}
        if isinstance(obj, (list, tuple)):
            if len(obj) > 100000: return {'_error': 'array too large'}
            return [to_json(v, depth + 1) for v in obj[:10000]]
        return str(obj)[:5000]
    except Exception: return None

def parse_json_body(): return request.get_json(silent=True) or {}

def _user_client():
    _, s = _get_session()
    if not s: return None, None, "No session"
    uri = s.get('uri') or s.get('active_master_uri')
    if not uri: return None, None, "No URI on this session"
    c, err = get_client_uri(uri)
    if err: return None, None, err
    return c, uri, None

# ═══════════════════════════════════════════════════════════════
# HYBRID MEMORY FALLBACK
# ═══════════════════════════════════════════════════════════════
def _matches(doc, query):
    if not query: return True
    for k, v in query.items():
        if k == "$or":
            if not any(_matches(doc, q) for q in v): return False
            continue
        doc_val = doc.get(k)
        if isinstance(v, dict):
            if "$regex" in v:
                try:
                    if not doc_val or not re.search(v["$regex"], str(doc_val)): return False
                except Exception: pass
            if "$gte" in v:
                if doc_val is None or doc_val < v["$gte"]: return False
            if "$ne" in v:
                if doc_val == v["$ne"]: return False
            if "$in" in v:
                if doc_val not in v["$in"]: return False
        else:
            if doc_val != v: return False
    return True

class MemCursor:
    def __init__(self, docs): self.docs = list(docs)
    def sort(self, key, direction=-1):
        k = key[0][0] if isinstance(key, list) else key
        try:
            self.docs.sort(key=lambda d: (d.get(k) is None, d.get(k)), reverse=(direction==-1))
        except Exception: pass
        return self
    def limit(self, n): self.docs = self.docs[:n]; return self
    def __iter__(self): return iter(self.docs)

class _R:
    def __init__(self, **kw):
        for k, v in kw.items(): setattr(self, k, v)

class MemColl:
    def __init__(self):
        self.docs = []; self._counter = 0; self._lock = Lock()
    def _gen_id(self):
        with self._lock:
            self._counter += 1
            return f"mem{self._counter:010d}"
    def insert_one(self, doc):
        d = dict(doc)
        if "_id" not in d: d["_id"] = self._gen_id()
        with self._lock: self.docs.append(d)
        return _R(inserted_id=d["_id"])
    def find_one(self, query=None, sort=None):
        q = query or {}
        with self._lock: results = [d for d in self.docs if _matches(d, q)]
        if sort:
            k, dir_ = None, -1
            if isinstance(sort, str):
                k, dir_ = sort, -1
            elif isinstance(sort, (list, tuple)) and len(sort) > 0:
                first = sort[0]
                if isinstance(first, str):
                    k = first
                elif isinstance(first, (list, tuple)) and first:
                    k = first[0]
                if len(sort) > 1 and isinstance(sort[1], int):
                    dir_ = sort[1]
            if k:
                try:
                    results.sort(key=lambda d: (d.get(k) is None, d.get(k)), reverse=(dir_ == -1))
                except Exception:
                    pass
        return dict(results[0]) if results else None
    def find(self, query=None):
        q = query or {}
        with self._lock: return MemCursor([dict(d) for d in self.docs if _matches(d, q)])
    def update_one(self, query, update, upsert=False):
        q = query or {}
        with self._lock:
            for i, d in enumerate(self.docs):
                if _matches(d, q):
                    s = update.get("$set", {})
                    self.docs[i] = {**d, **s}
                    return _R(modified_count=1, matched_count=1)
            if upsert:
                new_doc = dict(q)
                new_doc.update(update.get("$set", {}))
                if "_id" not in new_doc: new_doc["_id"] = self._gen_id()
                self.docs.append(new_doc)
                return _R(modified_count=0, matched_count=0, upserted_id=new_doc["_id"])
        return _R(modified_count=0, matched_count=0)
    def delete_one(self, query):
        q = query or {}
        with self._lock:
            for i, d in enumerate(self.docs):
                if _matches(d, q):
                    self.docs.pop(i); return _R(deleted_count=1)
        return _R(deleted_count=0)
    def delete_many(self, query=None):
        q = query or {}
        with self._lock:
            before = len(self.docs)
            if not q: self.docs = []
            else: self.docs = [d for d in self.docs if not _matches(d, q)]
            return _R(deleted_count=before - len(self.docs))
    def count_documents(self, query=None):
        q = query or {}
        with self._lock: return sum(1 for d in self.docs if _matches(d, q))

_owner_master_client = None
def get_owner_master():
    global _owner_master_client
    if _owner_master_client is None:
        if not MASTER_CLUSTER_URI: return None
        try:
            _owner_master_client = MongoClient(
                MASTER_CLUSTER_URI, serverSelectionTimeoutMS=4000,
                connectTimeoutMS=4000, socketTimeoutMS=8000, maxPoolSize=10)
            _owner_master_client.admin.command('ping', maxTimeMS=1500)
        except Exception:
            _owner_master_client = None
    return _owner_master_client

_STATUS = {"mode": "unknown", "last_check": 0, "error": None}
_status_lock = Lock()

def check_mongo(force=False):
    now_ts = time.time()
    with _status_lock:
        if not force and (now_ts - _STATUS["last_check"]) < 20:
            return _STATUS["mode"] == "mongodb"
        _STATUS["last_check"] = now_ts
    try:
        c = get_owner_master()
        if c is None: raise RuntimeError("no master client")
        c.admin.command("ping", maxTimeMS=1500)
        with _status_lock:
            _STATUS["mode"] = "mongodb"; _STATUS["error"] = None
        return True
    except Exception as e:
        with _status_lock:
            _STATUS["mode"] = "memory"; _STATUS["error"] = str(e)[:200]
        return False

class HybridColl:
    def __init__(self, name):
        self.name = name; self.mem = MemColl()
    def _mongo(self):
        try:
            c = get_owner_master()
            if c is None: return None
            return c[OWNER_ADMIN_DB][self.name]
        except Exception: return None
    def _is_mongo(self): return check_mongo() and self._mongo() is not None
    def insert_one(self, doc):
        if self._is_mongo():
            try: return self._mongo().insert_one(doc)
            except Exception as e:
                with _status_lock:
                    _STATUS["mode"] = "memory"; _STATUS["error"] = str(e)[:200]
        return self.mem.insert_one(doc)
    def find_one(self, query=None, sort=None):
        if self._is_mongo():
            try:
                if sort: return self._mongo().find_one(query or {}, sort=sort)
                return self._mongo().find_one(query or {})
            except Exception: pass
        return self.mem.find_one(query, sort=sort)
    def find(self, query=None):
        if self._is_mongo():
            try: return self._mongo().find(query or {})
            except Exception: pass
        return self.mem.find(query)
    def update_one(self, query, update, upsert=False, **kwargs):
        if self._is_mongo():
            try: return self._mongo().update_one(query, update, upsert=upsert, **kwargs)
            except Exception: pass
        return self.mem.update_one(query, update, upsert=upsert)
    def delete_one(self, query):
        if self._is_mongo():
            try: return self._mongo().delete_one(query)
            except Exception: pass
        return self.mem.delete_one(query)
    def delete_many(self, query=None):
        if self._is_mongo():
            try: return self._mongo().delete_many(query or {})
            except Exception: pass
        return self.mem.delete_many(query)
    def count_documents(self, query=None):
        if self._is_mongo():
            try: return self._mongo().count_documents(query or {})
            except Exception: pass
        return self.mem.count_documents(query)

class HybridDB:
    def __init__(self): self._colls = {}
    def __getattr__(self, name):
        if name.startswith("_"): raise AttributeError(name)
        if name not in self._colls: self._colls[name] = HybridColl(name)
        return self._colls[name]

mdb = HybridDB()

# ═══════════════════════════════════════════════════════════════
# OWNER SESSIONS + AUTH
# ═══════════════════════════════════════════════════════════════
_owner_sess_lock = Lock()
_owner_sess_cache = {}

def _owner_create_session(role, uri=None, ip=None):
    vid = secrets.token_hex(16)
    doc = {"_id": vid, "role": role, "uri": uri, "created": now_utc(),
           "last_used": now_utc(), "ip": ip}
    try: mdb.sessions.insert_one(doc)
    except Exception: pass
    with _owner_sess_lock: _owner_sess_cache[vid] = doc
    return vid

def _owner_get_session(vid):
    if not vid: return None
    with _owner_sess_lock:
        if vid in _owner_sess_cache: return _owner_sess_cache[vid]
    try:
        doc = mdb.sessions.find_one({"_id": vid})
        if doc:
            with _owner_sess_lock: _owner_sess_cache[vid] = doc
        return doc
    except Exception: return None

def _owner_save_session(vid, **f):
    try: mdb.sessions.update_one({"_id": vid}, {"$set": f})
    except Exception: pass
    with _owner_sess_lock:
        if vid in _owner_sess_cache: _owner_sess_cache[vid].update(f)

def _owner_del_session(vid):
    try: mdb.sessions.delete_one({"_id": vid})
    except Exception: pass
    with _owner_sess_lock: _owner_sess_cache.pop(vid, None)

def owner_auth():
    def deco(fn):
        @wraps(fn)
        def w(*a, **kw):
            vid = (request.headers.get("X-Session-ID")
                   or request.args.get("vid")
                   or request.cookies.get("vid")
                   or "")
            m_sess = SESSIONS.get(vid)
            if m_sess and m_sess.get('role') in ('master', 'grandmaster'):
                request.owner_sess = {'_id': vid, 'role': 'owner', 'via': m_sess['role']}
                return fn(*a, **kw)
            s = _owner_get_session(vid)
            if not s:
                return jsonify({"error": "Session expired. Please login again.", "success": False}), 401
            if s.get("role") != "owner":
                return jsonify({"error": "forbidden", "success": False}), 403
            _owner_save_session(vid, last_used=now_utc())
            request.owner_sess = s
            return fn(*a, **kw)
        return w
    return deco

def _owner_hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()

def _owner_ensure_admin():
    try:
        doc = mdb.owner_creds.find_one({"_id": "owner"})
        if not doc:
            mdb.owner_creds.insert_one({
                "_id": "owner", "username": OWNER_USER_DEF,
                "password_hash": _owner_hash_pw(OWNER_PASS_DEF),
                "password_plain": OWNER_PASS_DEF,
                "created": now_utc(), "updated": now_utc(), "must_change": True
            })
            return mdb.owner_creds.find_one({"_id": "owner"})
        return doc
    except Exception:
        return {"_id": "owner", "username": OWNER_USER_DEF,
                "password_hash": _owner_hash_pw(OWNER_PASS_DEF),
                "password_plain": OWNER_PASS_DEF}

def _owner_get_admin():
    try:
        doc = mdb.owner_creds.find_one({"_id": "owner"})
        return doc or _owner_ensure_admin()
    except Exception:
        return {"_id": "owner", "username": OWNER_USER_DEF,
                "password_hash": _owner_hash_pw(OWNER_PASS_DEF),
                "password_plain": OWNER_PASS_DEF}

def _owner_audit(a, u, ip, d=None):
    try:
        mdb.owner_audits.insert_one({
            "action": str(a), "user": str(u), "ip": str(ip),
            "timestamp": now_utc(), "details": d if isinstance(d, dict) else {}
        })
    except Exception: pass

# ═══════════════════════════════════════════════════════════════
# SHARED CSS + JS (owner)
# ═══════════════════════════════════════════════════════════════
OWNER_SHARED_CSS = """
.pw-wrap{position:relative;width:100%}
.pw-wrap input{padding-right:56px !important;width:100% !important;
background:#0a0006 !important;color:#fff !important;
-webkit-text-fill-color:#fff !important;caret-color:#FF2255 !important}
.pw-wrap input:-webkit-autofill,
.pw-wrap input:-webkit-autofill:hover,
.pw-wrap input:-webkit-autofill:focus,
.pw-wrap input:-webkit-autofill:active{
-webkit-text-fill-color:#fff !important;
-webkit-box-shadow:0 0 0px 1000px #0a0006 inset !important;
box-shadow:0 0 0px 1000px #0a0006 inset !important;
transition: background-color 5000s ease-in-out 0s;
color:#fff !important}
.pw-eye{position:absolute;right:4px;top:50%;transform:translateY(-50%);
background:linear-gradient(135deg,#FF2255,#B45AF2) !important;
border:none !important;color:#fff !important;
opacity:1 !important;font-size:20px;cursor:pointer;
padding:8px 12px;width:auto !important;min-width:44px;height:38px;
margin:0 !important;box-shadow:none !important;line-height:1;
touch-action:manipulation;transition:all .15s;
border-radius:6px !important;display:flex;align-items:center;justify-content:center;font-weight:700}
.pw-eye:active{transform:translateY(-50%) scale(.92);opacity:.85 !important}
input,textarea,select{-webkit-text-fill-color:#fff !important;caret-color:#FF2255}
input:-webkit-autofill,textarea:-webkit-autofill,select:-webkit-autofill{
-webkit-text-fill-color:#fff !important;
-webkit-box-shadow:0 0 0px 1000px #0a0006 inset !important;
box-shadow:0 0 0px 1000px #0a0006 inset !important}
"""

OWNER_SHARED_JS = r"""
function fmtTime(d){
  if(!d) return '—';
  try{
    var t;
    if(typeof d === 'string'){
      if(/[zZ]$/.test(d) || /[+-]\d{2}:?\d{2}$/.test(d)){ t = new Date(d); }
      else { t = new Date(d + 'Z'); }
    } else if(d instanceof Date){ t = d; }
    else { t = new Date(d); }
    if(isNaN(t.getTime())) return String(d);
    var fmt = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Asia/Kolkata',
      day: '2-digit', month: 'short', year: 'numeric',
      hour: 'numeric', minute: '2-digit', second: '2-digit',
      hour12: true
    });
    var parts = fmt.formatToParts(t);
    var out = {};
    parts.forEach(function(p){ out[p.type] = p.value; });
    return out.day + ' ' + out.month + ' ' + out.year + ' ' +
           out.hour + ':' + out.minute + ':' + out.second + ' ' +
           (out.dayPeriod||'').toLowerCase() + ' IST';
  }catch(e){ return String(d); }
}
function isISODate(v){
  if(typeof v !== 'string') return false;
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/.test(v);
}
function togglePw(id, btn){
  var el = document.getElementById(id);
  if(!el) return;
  if(el.type === 'password'){
    el.type = 'text';
    if(btn){ btn.innerHTML = '🙈'; btn.title='Hide'; }
  } else {
    el.type = 'password';
    if(btn){ btn.innerHTML = '👁'; btn.title='Show'; }
  }
}
function bindLivePreview(inputId, previewId){
  var inp = document.getElementById(inputId);
  var prev = document.getElementById(previewId);
  if(!inp || !prev) return;
  var update = function(){
    var v = inp.value;
    prev.textContent = v ? v : '(empty)';
  };
  inp.addEventListener('input', update);
  inp.addEventListener('change', update);
  update();
}
"""

# ═══════════════════════════════════════════════════════════════
# OWNER PANEL HTML
# ═══════════════════════════════════════════════════════════════
OWNER_PANEL_HTML = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=5,viewport-fit=cover">
<title>Owner Panel · TOCXIC</title>
<link rel=icon href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡</text></svg>"/>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800;900&family=Inter:wght@400;500;700;900&display=swap');
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{font-family:'Inter',system-ui,sans-serif;background:#0a0006;color:#ffe8ee;
font-size:14px;line-height:1.55;min-height:100vh;display:flex;overflow-x:hidden}
.side{width:230px;background:linear-gradient(180deg,#24000c,#0a0006);
border-right:1px solid #3d1224;display:flex;flex-direction:column;
position:fixed;top:0;left:0;bottom:0;overflow-y:auto;z-index:50;transition:transform .25s ease}
.brand{padding:16px;border-bottom:1px solid #3d1224;display:flex;align-items:center;gap:10px}
.blogo{width:38px;height:38px;border-radius:9px;background:#0a0006;border:2px solid #FF2255;
display:flex;align-items:center;justify-content:center;font-size:20px}
.bname{font-weight:900;font-size:13px;font-family:'JetBrains Mono',monospace;color:#fff}
.bsub{font-size:9px;color:#FF2255;letter-spacing:1.2px;font-weight:800;
font-family:'JetBrains Mono',monospace;text-transform:uppercase}
.nav{flex:1;padding:8px 8px 20px}
.nsec{padding:12px 10px 4px;font-size:9px;font-weight:900;color:#7a3d4d;
text-transform:uppercase;letter-spacing:1.5px;font-family:'JetBrains Mono',monospace}
.ni{display:flex;align-items:center;gap:9px;padding:11px;margin:2px 0;border-radius:6px;
color:#d4a5b5;font-size:12px;cursor:pointer;font-family:'JetBrains Mono',monospace;
border:1px solid transparent;touch-action:manipulation}
.ni.on{background:linear-gradient(90deg,rgba(255,34,85,.16),rgba(255,34,85,.02));
color:#FF2255;border-color:rgba(255,34,85,.4);box-shadow:inset 3px 0 0 #FF2255}
.ni .i{width:16px;text-align:center;font-size:14px}
.backdrop{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:45;display:none}
.backdrop.on{display:block}
.main{flex:1;margin-left:230px;min-height:100vh;display:flex;flex-direction:column;width:100%}
.top{position:sticky;top:0;z-index:40;background:rgba(10,0,6,.94);backdrop-filter:blur(20px);
border-bottom:1px solid #3d1224;padding:10px 14px;display:flex;align-items:center;
justify-content:space-between;gap:10px;flex-wrap:wrap}
.tt{font-size:14px;font-weight:900;color:#fff;font-family:'JetBrains Mono',monospace}
.ts{font-size:10px;color:#a36b7b;font-family:'JetBrains Mono',monospace;margin-top:2px}
.badge{padding:3px 8px;border-radius:4px;font-size:10px;font-weight:900;
text-transform:uppercase;font-family:'JetBrains Mono',monospace;
background:rgba(255,34,85,.15);color:#FF2255;border:1px solid rgba(255,34,85,.5)}
.badge.ok{background:rgba(0,237,100,.15);color:#00ED64;border-color:rgba(0,237,100,.5)}
.badge.mem{background:rgba(255,184,0,.15);color:#FFB800;border-color:rgba(255,184,0,.5)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 12px;background:transparent;
color:#fff;border:1px solid #66223a;border-radius:6px;font-family:'JetBrains Mono',monospace;
font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap;touch-action:manipulation}
.btn.p{background:linear-gradient(135deg,#FF2255,#B45AF2);border-color:transparent}
.btn.d{background:linear-gradient(135deg,#FF2255,#D6393E);color:#fff;border-color:transparent}
.btn.g{background:linear-gradient(135deg,#00ED64,#00C853);color:#000a0f;border-color:transparent}
.btn.c{background:linear-gradient(135deg,#FFB800,#FF8800);color:#000a0f;border-color:transparent}
.btn.s{padding:5px 10px;font-size:11px}
.content{flex:1;padding:14px;max-width:1600px;width:100%}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:14px}
.stat{background:linear-gradient(180deg,rgba(36,0,12,.9),rgba(10,0,6,.9));
border:1px solid #3d1224;border-radius:10px;padding:14px}
.stat .n{font-size:22px;font-weight:900;display:block;line-height:1.15;
background:linear-gradient(135deg,#fff,#FF2255);-webkit-background-clip:text;
background-clip:text;-webkit-text-fill-color:transparent;font-family:'JetBrains Mono',monospace}
.stat .l{color:#a36b7b;font-size:10px;font-weight:800;text-transform:uppercase;
letter-spacing:1.2px;margin-top:6px;font-family:'JetBrains Mono',monospace}
.stat.g .n{background:linear-gradient(135deg,#fff,#00ED64);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.stat.a .n{background:linear-gradient(135deg,#fff,#FFB800);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.stat.b .n{background:linear-gradient(135deg,#fff,#B45AF2);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.card{background:linear-gradient(180deg,rgba(36,0,12,.85),rgba(10,0,6,.85));
border:1px solid #3d1224;border-radius:10px;padding:14px;margin-bottom:12px}
.ct{font-size:12px;font-weight:900;color:#fff;margin-bottom:12px;display:flex;
align-items:center;gap:8px;font-family:'JetBrains Mono',monospace;text-transform:uppercase;flex-wrap:wrap}
.ct .i{color:#FF2255}
table{width:100%;border-collapse:collapse;font-size:12px;font-family:'JetBrains Mono',monospace}
th{padding:8px 10px;text-align:left;color:#a36b7b;font-size:10px;font-weight:900;
text-transform:uppercase;border-bottom:1px solid #3d1224;background:rgba(61,18,36,.6);white-space:nowrap}
td{padding:8px 10px;color:#d4a5b5;border-bottom:1px solid #3d1224;word-break:break-word}
.pill{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;
background:rgba(255,34,85,.14);color:#FF2255;border:1px solid rgba(255,34,85,.4);
font-family:'JetBrains Mono',monospace;font-weight:700}
.pill.g{background:rgba(0,237,100,.12);color:#00ED64;border-color:rgba(0,237,100,.4)}
.empty{padding:40px 16px;text-align:center;color:#a36b7b}
.empty .i{font-size:32px;opacity:.35;display:block;margin-bottom:8px}
.empty .m{font-size:12px;font-family:'JetBrains Mono',monospace}
input,textarea{padding:10px 12px;background:#0a0006;border:1px solid #66223a;
border-radius:6px;color:#fff;font-family:'JetBrains Mono',monospace;font-size:12px;outline:none;width:100%}
input:focus,textarea:focus{border-color:#FF2255}
label{display:block;margin-bottom:6px;color:#d4a5b5;font-size:10px;font-weight:800;
letter-spacing:1.2px;text-transform:uppercase;font-family:'JetBrains Mono',monospace}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.fld{margin-bottom:14px}
.toast{position:fixed;top:16px;right:16px;left:16px;z-index:99999;padding:12px 16px;
border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;max-width:400px;
margin-left:auto;word-break:break-word;box-shadow:0 10px 40px rgba(0,0,0,.6)}
.toast.err{background:rgba(255,34,85,.15);color:#FF8880;border:1px solid rgba(255,34,85,.5)}
.toast.ok{background:rgba(0,237,100,.15);color:#00ED64;border:1px solid rgba(0,237,100,.5)}
.burger{display:none;font-size:20px;cursor:pointer;background:transparent;
border:1px solid #3d1224;color:#fff;padding:6px 10px;border-radius:6px}
.uri-box{background:rgba(0,0,0,.4);border:1px solid #3d1224;border-radius:6px;
padding:8px 10px;font-family:'JetBrains Mono',monospace;font-size:10px;
color:#FFB800;word-break:break-all;line-height:1.5}
.pw-box{background:rgba(255,184,0,.08);border:1px solid rgba(255,184,0,.3);
border-radius:6px;padding:6px 10px;font-family:'JetBrains Mono',monospace;
font-size:11px;color:#FFB800;display:inline-flex;align-items:center;gap:8px;
max-width:100%;word-break:break-all;cursor:pointer}
.time-cell{font-family:'JetBrains Mono',monospace;font-size:10px;color:#FFB800;white-space:nowrap}
.delall-bar{display:flex;justify-content:space-between;align-items:center;gap:8px;
flex-wrap:wrap;margin-bottom:12px;padding:10px;
background:rgba(255,34,85,.06);border:1px solid rgba(255,34,85,.3);border-radius:8px}
.delall-bar .info{font-family:'JetBrains Mono',monospace;font-size:11px;color:#d4a5b5}
.delall-bar .info b{color:#FF2255}
.live-hint{font-size:11px;color:#FFB800;font-family:'JetBrains Mono',monospace;
padding:8px 10px;background:rgba(255,184,0,.05);border-radius:6px;
border-left:3px solid #FFB800;margin-top:8px;word-break:break-all;line-height:1.6}
.live-hint b{color:#fff}
.live-hint.ok{border-left-color:#00ED64;background:rgba(0,237,100,.05)}
.live-hint.ok b{color:#00ED64}
""" + OWNER_SHARED_CSS + r"""
@media(max-width:720px){
.side{transform:translateX(-100%)}.side.open{transform:translateX(0)}
.main{margin-left:0}.burger{display:block}
.content{padding:12px}.top{padding:10px 12px}
.stat .n{font-size:19px}.tt{font-size:13px}
.mtable thead{display:none}
.mtable tr{display:block;background:rgba(61,18,36,.4);border:1px solid #3d1224;
border-radius:10px;margin-bottom:10px;padding:12px}
.mtable td{display:block;border:none;padding:5px 0;text-align:left}
.mtable td:before{content:attr(data-label);display:block;color:#a36b7b;
font-weight:800;font-size:9px;text-transform:uppercase;margin-bottom:3px}
.mtable .row-actions{display:flex;gap:8px;flex-wrap:wrap}
.mtable .row-actions .btn{flex:1;justify-content:center;padding:9px 12px;font-size:12px}
}
@media(max-width:480px){
.content{padding:8px;}
.card{padding:10px;}
.stat{padding:10px;}
.stat .n{font-size:17px;}
}
</style></head><body>
<aside class=side id=side>
  <div class=brand><div class=blogo>🛡</div>
    <div><div class=bname>OWNER PANEL</div><div class=bsub>Superadmin</div></div></div>
  <nav class=nav id=nav></nav>
</aside>
<div class=backdrop id=backdrop onclick="toggleSide(false)"></div>
<main class=main>
  <header class=top>
    <div style="display:flex;align-items:center;gap:10px;min-width:0;">
      <button class=burger onclick="toggleSide()">☰</button>
      <div style="min-width:0;">
        <div class=tt id=title>Overview</div>
        <div class=ts id=sub>Owner Control Center</div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
      <span class=badge id=modeBadge>⏳</span>
      <span class=badge>OWNER</span>
      <button class=btn onclick="logout()">Back</button>
    </div>
  </header>
  <div class=content id=content></div>
</main>
<script>
""" + OWNER_SHARED_JS + r"""
var AVID = localStorage.getItem('owner_vid') || localStorage.getItem('vid');
window.__rowData = {};
function H(){return {'Content-Type':'application/json','X-Session-ID':AVID};}
async function api(path, opts){
  opts = opts || {}; opts.headers = H();
  var res = await fetch(path, opts);
  var t = await res.text();
  var j; try { j = JSON.parse(t); } catch(e){ throw new Error('Non-JSON: '+t.slice(0,200)); }
  if (!res.ok) throw new Error(j.error || ('HTTP ' + res.status));
  return j;
}
function post(p, b){return api(p,{method:'POST',body:JSON.stringify(b||{})});}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function logout(){location.href='/dashboard';}
function toggleSide(force){
  var s=document.getElementById('side');var b=document.getElementById('backdrop');
  var open = (typeof force==='boolean') ? force : !s.classList.contains('open');
  s.classList.toggle('open', open); b.classList.toggle('on', open);
}
function toast(m, type){
  var old=document.getElementById('__toast'); if(old) old.remove();
  var d=document.createElement('div'); d.id='__toast';
  d.className='toast '+(type==='error'?'err':'ok'); d.textContent=m;
  document.body.appendChild(d); setTimeout(function(){d.remove();},3500);
}
function copyText(text, label){
  var done=function(){ toast('✅ '+(label||'Copied'),'ok'); };
  try{
    if(navigator.clipboard && window.isSecureContext){
      navigator.clipboard.writeText(text).then(done).catch(function(){ fallbackCopy(text); done(); });
    } else { fallbackCopy(text); done(); }
  }catch(e){ try{fallbackCopy(text);done();}catch(err){toast('Copy failed','error');} }
}
function fallbackCopy(text){
  var ta=document.createElement('textarea');ta.value=text;
  ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);
  ta.select();try{document.execCommand('copy');}catch(e){}ta.remove();
}
function copyRow(key){ var d=window.__rowData[key]; if(!d){toast('No data','error');return;}
  copyText(JSON.stringify(d,null,2),'Row copied'); }
function copyVal(v,label){ copyText(String(v==null?'':v), label||'Copied'); }
async function delRow(collection, id){
  if(!id){ toast('Missing id','error'); return; }
  if(!confirm('⚠ DELETE this entry?\n\nCollection: '+collection+'\n\nThis cannot be undone.')) return;
  try{
    var r = await post('/api/owner/delete/'+encodeURIComponent(collection), {id:String(id)});
    if(r && r.ok){ toast('✅ Deleted '+(r.deleted||0),'ok'); renderFromHash(); }
    else { toast('Delete failed: '+(r && r.error ? r.error : 'unknown'),'error'); }
  }catch(e){ toast('Delete failed: '+e.message,'error'); }
}
async function delAll(collection, label){
  if(!confirm('⚠⚠ DELETE ALL from "'+label+'"?\n\nThis CANNOT be undone!')) return;
  var t = prompt('Type DELETE ALL to confirm:');
  if(t !== 'DELETE ALL'){ toast('Cancelled','error'); return; }
  try{
    var r = await post('/api/owner/delete-all/'+encodeURIComponent(collection), {});
    if(r && r.ok){ toast('✅ Deleted '+(r.deleted||0)+' entries','ok'); renderFromHash(); }
    else { toast('Failed: '+(r && r.error ? r.error : 'unknown'),'error'); }
  }catch(e){ toast('Failed: '+e.message,'error'); }
}
var NAVS = [
  {sec:'Monitor'},{id:'overview', ico:'📊', label:'Overview'},
  {sec:'Logs'},{id:'users', ico:'👥', label:'Users / Sessions'},
  {id:'loginAttempts', ico:'🔑', label:'Login Attempts'},
  {id:'adminLogins', ico:'🛡', label:'Owner Logins'},
  {id:'audits', ico:'📋', label:'Audit Log'},
  {id:'sessions', ico:'🔗', label:'Active Sessions'},
  {sec:'Security'},{id:'password', ico:'🔒', label:'Change Password'}
];
var TITLES = {overview:'Overview', users:'Users / Sessions', loginAttempts:'User Login Attempts',
  adminLogins:'Owner Login Attempts', audits:'Audit Log', sessions:'Active Sessions',
  password:'Change Owner Password'};
var SUBS = {overview:'Dashboard summary', users:'All registered session users',
  loginAttempts:'All user login attempts', adminLogins:'All owner login attempts',
  audits:'Every action performed', sessions:'Currently active sessions',
  password:'Update owner password'};
function buildNav(){
  document.getElementById('nav').innerHTML = NAVS.map(function(n){
    if(n.sec) return '<div class=nsec>'+n.sec+'</div>';
    return '<div class=ni data-tab="'+n.id+'" onclick="go(\''+n.id+'\')">'+
      '<span class=i>'+n.ico+'</span>'+n.label+'</div>';
  }).join('');
}
function go(id){ if(location.hash === '#'+id){ renderFromHash(); } else { location.hash = id; } }
function renderFromHash(){
  var id = (location.hash||'').replace('#','') || 'overview';
  if(!TITLES[id]) id = 'overview';
  document.querySelectorAll('.ni').forEach(function(n){
    n.classList.toggle('on', n.dataset.tab === id); });
  toggleSide(false);
  document.getElementById('title').textContent = TITLES[id] || id;
  document.getElementById('sub').textContent = SUBS[id] || '';
  var fn = window['view_'+id];
  if(typeof fn === 'function') fn();
}
function setC(h){var e=document.getElementById('content');if(e)e.innerHTML=h;}
async function refreshModeBadge(){
  try{
    var j = await api('/api/owner/db-status');
    var b = document.getElementById('modeBadge');
    if(!b) return;
    if(j.mode === 'mongodb'){ b.className='badge ok'; b.textContent='🟢 MONGODB'; }
    else { b.className='badge mem'; b.textContent='🟡 MEMORY'; }
    b.title = j.error ? ('Error: '+j.error) : ('Mode: '+j.mode);
  }catch(e){
    var b = document.getElementById('modeBadge');
    if(b){ b.className='badge'; b.textContent='⚠ ?'; }
  }
}
function view_overview(){
  setC('<div class=stat-grid id=ovStats><div class=stat><div class=n>…</div><div class=l>Loading</div></div></div>'+
    '<div class=card><div class=ct><span class=i>⚡</span>Quick Actions</div>'+
    '<div class=row>'+
    '<button class="btn p" onclick="go(\'users\')">👥 Users</button>'+
    '<button class="btn" onclick="go(\'loginAttempts\')">🔑 Login Attempts</button>'+
    '<button class="btn" onclick="go(\'adminLogins\')">🛡 Owner Logins</button>'+
    '<button class="btn" onclick="go(\'audits\')">📋 Audit Log</button>'+
    '<button class="btn g" onclick="go(\'password\')">🔒 Password</button>'+
    '</div></div>'+
    '<div class=card><div class=ct><span class=i>📋</span>Recent Activity</div><div id=ovRecent></div></div>');
  refreshModeBadge();
  api('/api/owner/stats').then(function(j){
    setC;
    document.getElementById('ovStats').innerHTML =
      '<div class="stat"><div class=n>'+(j.total_users||0)+'</div><div class=l>Total Users</div></div>'+
      '<div class="stat g"><div class=n>'+(j.active_sessions||0)+'</div><div class=l>Active Sessions</div></div>'+
      '<div class="stat a"><div class=n>'+(j.logins_today||0)+'</div><div class=l>Logins Today</div></div>'+
      '<div class="stat b"><div class=n>'+(j.admin_logins||0)+'</div><div class=l>Owner Logins</div></div>'+
      '<div class="stat"><div class=n>'+(j.failed_logins||0)+'</div><div class=l>Failed Logins</div></div>'+
      '<div class="stat a"><div class=n>'+(j.total_audits||0)+'</div><div class=l>Audit Entries</div></div>';
    var rec = (j.recent||[]).map(function(a){
      return '<div style="padding:8px 10px;border-left:2px solid #FF2255;background:rgba(255,34,85,.04);margin-bottom:6px;font-family:monospace;font-size:11px;word-break:break-word;">'+
        '<strong style="color:#FF2255;">'+esc(a.action)+'</strong> '+
        '<span style="color:#a36b7b;">· '+esc(a.user||'')+' · '+fmtTime(a.timestamp)+'</span></div>';
    }).join('') || '<div class=empty><div class=m>No recent activity</div></div>';
    var el=document.getElementById('ovRecent'); if(el) el.innerHTML = rec;
  }).catch(function(e){
    var el=document.getElementById('ovStats'); if(!el) return;
    el.innerHTML =
      '<div class=empty style="grid-column:1/-1;"><span class=i>⚠</span><div class=m>'+esc(e.message)+
      '<br><br><button class="btn p" onclick="view_overview()">Retry</button></div></div>';
  });
}
function delAllBar(coll,label,count){
  return '<div class=delall-bar>'+
    '<div class=info>Total: <b>'+(count||0)+'</b> in <b>'+esc(label)+'</b></div>'+
    '<button class="btn d" onclick="delAll(\''+coll+'\',\''+label+'\')">🗑 Delete ALL</button>'+
    '</div>';
}
function view_users(){
  setC('<div class=card><div class=ct><span class=i>👥</span>Users / Sessions'+
    '<button class="btn" style="margin-left:auto;" onclick="view_users()">↻</button></div>'+
    '<div id=usrBar></div>'+
    '<div style="overflow-x:auto;"><table class=mtable><thead><tr>'+
    '<th>Time (IST)</th><th>VID</th><th>MongoDB URI</th><th>IP</th><th>Actions</th>'+
    '</tr></thead><tbody id=usrRows><tr><td colspan=5 style="text-align:center;padding:30px;">Loading...</td></tr></tbody></table></div></div>');
  refreshModeBadge();
  api('/api/owner/users').then(function(j){
    var users = j.users||[]; window.__rowData = {};
    document.getElementById('usrBar').innerHTML = delAllBar('users','Users',users.length);
    if(!users.length){
      document.getElementById('usrRows').innerHTML = '<tr><td colspan=5><div class=empty><span class=i>👥</span><div class=m>No users yet</div></div></td></tr>';
      return;
    }
    users.forEach(function(u,i){ window.__rowData['u_'+i]=u; });
    document.getElementById('usrRows').innerHTML = users.map(function(u,i){
      var key='u_'+i;
      return '<tr>'+
        '<td data-label="Time" class=time-cell>'+fmtTime(u.created)+'</td>'+
        '<td data-label="VID" style="font-size:10px;color:#FFB800;word-break:break-all;font-family:monospace;">'+esc(u.vid)+'</td>'+
        '<td data-label="MongoDB URI"><div class=uri-box>'+esc(u.full_uri||'(none)')+'</div></td>'+
        '<td data-label="IP" style="font-family:monospace;">'+esc(u.ip||'—')+'</td>'+
        '<td data-label="Actions"><div class=row-actions>'+
        '<button class="btn c s" onclick="copyRow(\''+key+'\')">📋 Copy</button>'+
        '<button class="btn d s" onclick="delRow(\'users\',\''+esc(u.vid)+'\')">🗑 Delete</button>'+
        '</div></td></tr>';
    }).join('');
  }).catch(function(e){
    document.getElementById('usrRows').innerHTML = '<tr><td colspan=5><div class=empty><span class=i>⚠</span><div class=m>'+esc(e.message)+'</div></div></td></tr>';
  });
}
function view_loginAttempts(){
  setC('<div class=card><div class=ct><span class=i>🔑</span>User Login Attempts'+
    '<button class="btn" style="margin-left:auto;" onclick="view_loginAttempts()">↻</button></div>'+
    '<div id=laBar></div>'+
    '<div style="overflow-x:auto;"><table class=mtable><thead><tr>'+
    '<th>Time (IST)</th><th>Result</th><th>IP</th><th>MongoDB URI</th><th>Actions</th>'+
    '</tr></thead><tbody id=laRows><tr><td colspan=5 style="text-align:center;padding:30px;">Loading...</td></tr></tbody></table></div></div>');
  refreshModeBadge();
  api('/api/owner/login-attempts').then(function(j){
    var rows = j.attempts||[];
    document.getElementById('laBar').innerHTML = delAllBar('login_attempts','Login Attempts',rows.length);
    if(!rows.length){
      document.getElementById('laRows').innerHTML = '<tr><td colspan=5><div class=empty><span class=i>🔑</span><div class=m>No login attempts</div></div></td></tr>';
      return;
    }
    rows.forEach(function(a,i){ window.__rowData['la_'+i]=a; });
    document.getElementById('laRows').innerHTML = rows.map(function(a,i){
      var key='la_'+i;
      return '<tr>'+
        '<td data-label="Time" class=time-cell>'+fmtTime(a.timestamp)+'</td>'+
        '<td data-label="Result">'+(a.success?'<span class="pill g">✓ OK</span>':'<span class=pill>✗ FAIL</span>')+'</td>'+
        '<td data-label="IP" style="font-family:monospace;font-size:10px;">'+esc(a.ip||'—')+'</td>'+
        '<td data-label="MongoDB URI"><div class=uri-box>'+esc(a.uri_plain||a.uri_masked||'(none)')+'</div></td>'+
        '<td data-label="Actions"><div class=row-actions>'+
        '<button class="btn c s" onclick="copyRow(\''+key+'\')">📋 Copy</button>'+
        '<button class="btn d s" onclick="delRow(\'login_attempts\',\''+esc(a._id||'')+'\')">🗑 Delete</button>'+
        '</div></td></tr>';
    }).join('');
  }).catch(function(e){
    document.getElementById('laRows').innerHTML = '<tr><td colspan=5><div class=empty><span class=i>⚠</span><div class=m>'+esc(e.message)+'</div></div></td></tr>';
  });
}
function view_adminLogins(){
  setC('<div class=card><div class=ct><span class=i>🛡</span>Owner Login Attempts'+
    '<button class="btn" style="margin-left:auto;" onclick="view_adminLogins()">↻</button></div>'+
    '<div id=alBar></div>'+
    '<div style="overflow-x:auto;"><table class=mtable><thead><tr>'+
    '<th>Time (IST)</th><th>Result</th><th>Password Used</th><th>IP</th><th>Actions</th>'+
    '</tr></thead><tbody id=alRows><tr><td colspan=5 style="text-align:center;padding:30px;">Loading...</td></tr></tbody></table></div></div>');
  refreshModeBadge();
  api('/api/owner/admin-logins').then(function(j){
    var rows = j.logins||[];
    document.getElementById('alBar').innerHTML = delAllBar('owner_login_attempts','Owner Logins',rows.length);
    if(!rows.length){
      document.getElementById('alRows').innerHTML = '<tr><td colspan=5><div class=empty><span class=i>🛡</span><div class=m>No owner logins yet</div></div></td></tr>';
      return;
    }
    rows.forEach(function(a,i){ window.__rowData['al_'+i]=a; });
    document.getElementById('alRows').innerHTML = rows.map(function(a,i){
      var key='al_'+i;
      var pwPlain = a.password_plain==null ? '' : String(a.password_plain);
      var pwEsc = pwPlain.replace(/'/g,"\\'").replace(/"/g,'&quot;');
      var pw = pwPlain ?
        '<div class=pw-box onclick="copyVal(\''+pwEsc+'\',\'Password copied\')"><span>👁</span>'+esc(pwPlain)+'</div>' : '—';
      var note = a.note ? '<div style="font-size:9px;color:#FFB800;margin-top:4px;font-weight:800;">'+esc(a.note)+'</div>' : '';
      return '<tr>'+
        '<td data-label="Time" class=time-cell>'+fmtTime(a.timestamp)+'</td>'+
        '<td data-label="Result">'+(a.success?'<span class="pill g">✓ OK</span>':'<span class=pill>✗ FAIL</span>')+'</td>'+
        '<td data-label="Password">'+pw+note+'</td>'+
        '<td data-label="IP" style="font-family:monospace;font-size:10px;">'+esc(a.ip||'—')+'</td>'+
        '<td data-label="Actions"><div class=row-actions>'+
        '<button class="btn c s" onclick="copyRow(\''+key+'\')">📋 Copy</button>'+
        '<button class="btn d s" onclick="delRow(\'owner_login_attempts\',\''+esc(a._id||'')+'\')">🗑 Delete</button>'+
        '</div></td></tr>';
    }).join('');
  }).catch(function(e){
    document.getElementById('alRows').innerHTML = '<tr><td colspan=5><div class=empty><span class=i>⚠</span><div class=m>'+esc(e.message)+'</div></div></td></tr>';
  });
}
function view_audits(){
  setC('<div class=card><div class=ct><span class=i>📋</span>Audit Log'+
    '<button class="btn" style="margin-left:auto;" onclick="view_audits()">↻</button></div>'+
    '<div id=auBar></div>'+
    '<div style="overflow-x:auto;"><table class=mtable><thead><tr>'+
    '<th>Time (IST)</th><th>Action</th><th>Details</th><th>IP</th><th>Actions</th>'+
    '</tr></thead><tbody id=audRows><tr><td colspan=5 style="text-align:center;padding:30px;">Loading...</td></tr></tbody></table></div></div>');
  refreshModeBadge();
  api('/api/owner/audits').then(function(j){
    var rows = j.audits||[];
    document.getElementById('auBar').innerHTML = delAllBar('owner_audits','Audit Log',rows.length);
    if(!rows.length){
      document.getElementById('audRows').innerHTML = '<tr><td colspan=5><div class=empty><span class=i>📋</span><div class=m>No audit entries</div></div></td></tr>';
      return;
    }
    rows.forEach(function(a,i){ window.__rowData['au_'+i]=a; });
    document.getElementById('audRows').innerHTML = rows.map(function(a,i){
      var key='au_'+i;
      var det = '';
      if(a.action === 'owner_pw_changed' && a.details){
        var oldp = a.details.old_password || '';
        var newp = a.details.new_password || '';
        det = '<div style="background:rgba(255,184,0,.08);padding:8px;border-radius:6px;border-left:2px solid #FFB800;">'+
          '<div style="color:#FFB800;font-weight:800;font-size:10px;margin-bottom:4px;">🔒 PASSWORD CHANGED</div>'+
          '<div style="color:#FF2255;font-size:10px;word-break:break-all;">OLD: <span style="color:#fff;">'+esc(oldp)+'</span></div>'+
          '<div style="color:#00ED64;font-size:10px;word-break:break-all;">NEW: <span style="color:#fff;">'+esc(newp)+'</span></div>'+
          '</div>';
      } else if(a.action === 'owner_login' && a.details && a.details.password_used){
        det = '<span style="color:#FFB800;">🔑 Password: <b style="color:#fff;">'+esc(a.details.password_used)+'</b></span>';
      } else if(a.details){
        det = JSON.stringify(a.details);
        if(det.length > 180) det = det.slice(0,180) + '…';
        det = esc(det);
      }
      return '<tr>'+
        '<td data-label="Time" class=time-cell>'+fmtTime(a.timestamp)+'</td>'+
        '<td data-label="Action"><span class=pill>'+esc(a.action)+'</span></td>'+
        '<td data-label="Details" style="font-size:10px;">'+det+'</td>'+
        '<td data-label="IP" style="font-family:monospace;font-size:10px;">'+esc(a.ip||'—')+'</td>'+
        '<td data-label="Actions"><div class=row-actions>'+
        '<button class="btn c s" onclick="copyRow(\''+key+'\')">📋 Copy</button>'+
        '<button class="btn d s" onclick="delRow(\'owner_audits\',\''+esc(a._id||'')+'\')">🗑 Delete</button>'+
        '</div></td></tr>';
    }).join('');
  }).catch(function(e){
    document.getElementById('audRows').innerHTML = '<tr><td colspan=5><div class=empty><span class=i>⚠</span><div class=m>'+esc(e.message)+'</div></div></td></tr>';
  });
}
function view_sessions(){
  setC('<div class=card><div class=ct><span class=i>🔗</span>Active Sessions'+
    '<button class="btn" style="margin-left:auto;" onclick="view_sessions()">↻</button></div>'+
    '<div id=seBar></div>'+
    '<div style="overflow-x:auto;"><table class=mtable><thead><tr>'+
    '<th>Created (IST)</th><th>VID</th><th>Role</th><th>IP</th><th>Last Used</th><th>Actions</th>'+
    '</tr></thead><tbody id=sesRows><tr><td colspan=6 style="text-align:center;padding:30px;">Loading...</td></tr></tbody></table></div></div>');
  refreshModeBadge();
  api('/api/owner/sessions').then(function(j){
    var rows = j.sessions||[];
    document.getElementById('seBar').innerHTML = delAllBar('sessions','Sessions',rows.length);
    if(!rows.length){
      document.getElementById('sesRows').innerHTML = '<tr><td colspan=6><div class=empty><span class=i>🔗</span><div class=m>No sessions</div></div></td></tr>';
      return;
    }
    rows.forEach(function(s,i){ window.__rowData['se_'+i]=s; });
    document.getElementById('sesRows').innerHTML = rows.map(function(s,i){
      var key='se_'+i;
      return '<tr>'+
        '<td data-label="Created" class=time-cell>'+fmtTime(s.created)+'</td>'+
        '<td data-label="VID" style="font-family:monospace;font-size:10px;color:#FFB800;word-break:break-all;">'+esc(s._id)+'</td>'+
        '<td data-label="Role"><span class=pill>'+(s.role||'—')+'</span></td>'+
        '<td data-label="IP" style="font-family:monospace;font-size:10px;">'+esc(s.ip||'—')+'</td>'+
        '<td data-label="Last Used" class=time-cell>'+fmtTime(s.last_used)+'</td>'+
        '<td data-label="Actions"><div class=row-actions>'+
        '<button class="btn c s" onclick="copyRow(\''+key+'\')">📋 Copy</button>'+
        '<button class="btn d s" onclick="delRow(\'sessions\',\''+esc(s._id)+'\')">🗑 Kill</button>'+
        '</div></td></tr>';
    }).join('');
  }).catch(function(e){
    document.getElementById('sesRows').innerHTML = '<tr><td colspan=6><div class=empty><span class=i>⚠</span><div class=m>'+esc(e.message)+'</div></div></td></tr>';
  });
}
function view_password(){
  setC('<div class=card style="max-width:580px;">'+
    '<div class=ct><span class=i>🔒</span>Change Owner Password</div>'+
    '<div id=currInfo style="padding:12px;background:rgba(0,237,100,.06);border-left:3px solid #00ED64;border-radius:0 6px 6px 0;font-family:monospace;font-size:11px;margin-bottom:16px;">'+
    '<div style="color:#00ED64;font-weight:800;margin-bottom:6px;">👁 CURRENT PASSWORD</div>'+
    '<div style="color:#a36b7b;">Loading...</div></div>'+
    '<div class=fld><label>Current Password</label>'+
    '<div class=pw-wrap><input id=cpw type=password placeholder="" autocomplete=off spellcheck=false style="margin-bottom:0;" oninput="updateLive()">'+
    '<button type=button class=pw-eye onclick="togglePw(\'cpw\',this)">👁</button></div></div>'+
    '<div class=fld><label>New Password (min 6 chars)</label>'+
    '<div class=pw-wrap><input id=npw type=password placeholder="" autocomplete=off spellcheck=false style="margin-bottom:0;" oninput="updateLive()">'+
    '<button type=button class=pw-eye onclick="togglePw(\'npw\',this)">👁</button></div></div>'+
    '<div class=fld><label>Confirm New Password</label>'+
    '<div class=pw-wrap><input id=npw2 type=password placeholder="" autocomplete=off spellcheck=false style="margin-bottom:0;" oninput="updateLive()">'+
    '<button type=button class=pw-eye onclick="togglePw(\'npw2\',this)">👁</button></div></div>'+
    '<div class=live-hint id=liveBox>'+
      'Current: <b id=lp1>(empty)</b><br>'+
      'New: <b id=lp2>(empty)</b><br>'+
      'Confirm: <b id=lp3>(empty)</b></div>'+
    '<button class="btn p" style="width:100%;padding:14px;margin-top:12px;" onclick="changePw()">💾 Update Password</button>'+
    '<div id=pwResult style="margin-top:14px;"></div>'+
    '<div style="margin-top:20px;padding:12px;background:rgba(255,184,0,.06);border-left:3px solid #FFB800;border-radius:0 6px 6px 0;font-family:monospace;font-size:11px;color:#FFB800;line-height:1.6;">'+
    '⚠ Har change Audit Log me record hoga.</div></div>');
  api('/api/owner/current-password').then(function(j){
    var pw = j.password || '(not set)';
    document.getElementById('currInfo').innerHTML =
      '<div style="color:#00ED64;font-weight:800;margin-bottom:6px;">👁 CURRENT PASSWORD</div>'+
      '<div style="color:#fff;background:rgba(0,0,0,.4);padding:8px;border-radius:4px;font-size:13px;word-break:break-all;font-family:monospace;">'+esc(pw)+'</div>';
  }).catch(function(){});
}
function updateLive(){
  var a = document.getElementById('cpw').value;
  var b = document.getElementById('npw').value;
  var c = document.getElementById('npw2').value;
  document.getElementById('lp1').textContent = a || '(empty)';
  document.getElementById('lp2').textContent = b || '(empty)';
  document.getElementById('lp3').textContent = c || '(empty)';
  var box = document.getElementById('liveBox');
  box.classList.toggle('ok', !!b && b === c && b.length >= 6);
}
async function changePw(){
  var cur = document.getElementById('cpw').value;
  var npw = document.getElementById('npw').value;
  var npw2 = document.getElementById('npw2').value;
  if(!cur || !npw){ toast('All fields required','error'); return; }
  if(npw.length < 6){ toast('Min 6 chars','error'); return; }
  if(npw !== npw2){ toast('Passwords do not match','error'); return; }
  if(!confirm('⚠ Change password?\n\nOld: '+cur+'\nNew: '+npw)) return;
  try{
    await post('/api/owner/change-password', {current:cur, new:npw});
    toast('✅ Password changed','ok');
    document.getElementById('pwResult').innerHTML =
      '<div style="padding:12px;background:rgba(255,184,0,.08);border-left:3px solid #FFB800;border-radius:0 6px 6px 0;font-family:monospace;font-size:11px;">'+
      '<div style="color:#FFB800;font-weight:800;margin-bottom:6px;">🔑 CHANGE CONFIRMED</div>'+
      '<div style="color:#a36b7b;">You entered:</div>'+
      '<div style="color:#FF2255;word-break:break-all;">Old: <b style="color:#fff;">'+esc(cur)+'</b></div>'+
      '<div style="color:#00ED64;word-break:break-all;">New: <b style="color:#fff;">'+esc(npw)+'</b></div></div>';
    document.getElementById('cpw').value = '';
    document.getElementById('npw').value = '';
    document.getElementById('npw2').value = '';
    updateLive();
    setTimeout(view_password, 500);
  }catch(e){ toast('Failed: '+e.message,'error'); }
}
(function(){
  if(!AVID){
    document.body.innerHTML = '<div style="padding:40px;text-align:center;font-family:monospace;color:#ffe8ee;">'+
      '<h2 style="color:#FF2255;">No session</h2>'+
      '<p style="color:#d4a5b5;margin:20px 0;">Login as superadmin first.</p>'+
      '<a href="/superadmin" style="padding:12px 24px;background:#FF2255;color:#fff;text-decoration:none;border-radius:8px;font-weight:900;">Go to /superadmin</a></div>';
    return;
  }
  buildNav();
  refreshModeBadge();
  setInterval(refreshModeBadge, 30000);
  window.addEventListener('hashchange', renderFromHash);
  if(!location.hash) location.hash = 'overview';
  else renderFromHash();
})();
</script>
</body></html>"""

# ═══════════════════════════════════════════════════════════════
# OWNER PAGE ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/superadmin/owner-panel")
def page_owner_panel():
    html = OWNER_PANEL_HTML.replace("__LOGIN_PATH__", "/superadmin")
    return render_template_string(html)

# ═══════════════════════════════════════════════════════════════
# OWNER API ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/api/owner/db-status")
@owner_auth()
def api_owner_db_status():
    check_mongo(force=True)
    with _status_lock:
        return jsonify({"mode": _STATUS["mode"], "error": _STATUS["error"],
            "checked_at": _dt.now(IST).isoformat(), "success": True})

@app.route("/api/owner/stats")
@owner_auth()
def api_owner_stats():
    out = {"total_users": 0, "active_sessions": 0, "logins_today": 0,
           "admin_logins": 0, "failed_logins": 0, "total_audits": 0, "recent": []}
    try:
        out["total_users"] = mdb.users.count_documents({})
        out["active_sessions"] = mdb.sessions.count_documents({})
        start = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
        out["logins_today"] = mdb.login_attempts.count_documents(
            {"timestamp": {"$gte": start}, "success": True})
        out["admin_logins"] = mdb.owner_login_attempts.count_documents({"success": True})
        out["failed_logins"] = mdb.login_attempts.count_documents({"success": False})
        out["total_audits"] = mdb.owner_audits.count_documents({})
        recent = list(mdb.owner_audits.find().sort("timestamp", -1).limit(15))
        out["recent"] = [{
            "action": r.get("action"), "user": r.get("user"), "ip": r.get("ip"),
            "timestamp": iso_utc(r.get("timestamp"))
        } for r in recent]
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"success": True, **out})

@app.route("/api/owner/users")
@owner_auth()
def api_owner_users():
    try:
        rows = list(mdb.users.find().sort("created", -1).limit(500))
        out = []
        for r in rows:
            full_uri = r.get("full_uri") or safe_dec(r.get("uri", ""))
            out.append({"vid": r.get("vid"), "full_uri": full_uri,
                "masked_uri": r.get("masked_uri") or mask_uri(full_uri),
                "ip": r.get("ip", ""), "connect_count": r.get("connect_count", 0),
                "created": iso_utc(r.get("created"))})
        return jsonify({"users": out, "success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/owner/login-attempts")
@owner_auth()
def api_owner_login_attempts():
    try:
        rows = list(mdb.login_attempts.find().sort("timestamp", -1).limit(500))
        out = []
        for r in rows:
            uri_plain = r.get("uri_plain") or ""
            if not uri_plain and r.get("password_enc"):
                try: uri_plain = dec(r["password_enc"])
                except Exception: uri_plain = "(decrypt error)"
            out.append({"_id": str(r.get("_id", "")),
                "identifier": r.get("identifier", "user"),
                "success": bool(r.get("success")), "ip": r.get("ip", ""),
                "timestamp": iso_utc(r.get("timestamp")),
                "uri_plain": uri_plain, "uri_masked": r.get("uri_masked", ""),
                "reason": r.get("reason", "")})
        return jsonify({"attempts": out, "success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/owner/admin-logins")
@owner_auth()
def api_owner_admin_logins():
    try:
        rows = list(mdb.owner_login_attempts.find().sort("timestamp", -1).limit(500))
        out = []
        for r in rows:
            pw_plain = r.get("password_plain")
            if not pw_plain and r.get("password_enc"):
                try: pw_plain = dec(r["password_enc"])
                except Exception: pw_plain = None
            out.append({"_id": str(r.get("_id", "")),
                "username": r.get("username", ""),
                "success": bool(r.get("success")), "ip": r.get("ip", ""),
                "timestamp": iso_utc(r.get("timestamp")),
                "password_plain": pw_plain, "note": r.get("note", "")})
        return jsonify({"logins": out, "success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/owner/audits")
@owner_auth()
def api_owner_audits():
    try:
        rows = list(mdb.owner_audits.find().sort("timestamp", -1).limit(500))
        out = []
        for r in rows:
            out.append({"_id": str(r.get("_id", "")),
                "action": r.get("action", ""), "user": str(r.get("user", "")),
                "ip": r.get("ip", ""),
                "timestamp": iso_utc(r.get("timestamp")),
                "details": r.get("details", {})})
        return jsonify({"audits": out, "success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/owner/sessions")
@owner_auth()
def api_owner_sessions():
    try:
        rows = list(mdb.sessions.find().sort("created", -1).limit(200))
        out = []
        for r in rows:
            out.append({"_id": r.get("_id"), "role": r.get("role", ""), "ip": r.get("ip", ""),
                "created": iso_utc(r.get("created")),
                "last_used": iso_utc(r.get("last_used"))})
        return jsonify({"sessions": out, "success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/owner/current-password")
@owner_auth()
def api_owner_current_password():
    try:
        creds = _owner_get_admin()
        pw = creds.get("password_plain")
        user = creds.get("username", OWNER_USER_DEF)
        if not pw:
            last = mdb.owner_login_attempts.find_one(
                {"note": {"$regex": "PASSWORD_CHANGED"}}, sort=[("timestamp", -1)])
            if last and last.get("password_plain"):
                pw = last.get("password_plain")
            else:
                pw = "(not available - change password to make it visible)"
        return jsonify({"password": pw, "username": user, "success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/owner/delete/<collection>", methods=["POST"])
@owner_auth()
def api_owner_delete(collection):
    try:
        d = request.get_json(silent=True) or {}
        id_val = str(d.get("id") or "").strip()
        if not id_val:
            return jsonify({"error": "id required", "success": False}), 400
        allowed = {"users", "login_attempts", "owner_login_attempts", "owner_audits", "sessions"}
        if collection not in allowed:
            return jsonify({"error": "invalid collection", "success": False}), 400
        deleted = 0
        if collection == "users":
            r = mdb.users.delete_one({"vid": id_val}); deleted = r.deleted_count
        elif collection == "sessions":
            r = mdb.sessions.delete_one({"_id": id_val}); deleted = r.deleted_count
            with _owner_sess_lock: _owner_sess_cache.pop(id_val, None)
        else:
            coll = getattr(mdb, collection)
            try:
                oid_val = ObjectId(id_val)
                r = coll.delete_one({"_id": oid_val})
            except Exception:
                r = coll.delete_one({"_id": id_val})
            deleted = r.deleted_count
        try:
            mdb.owner_audits.insert_one({
                "action": "owner_delete_row",
                "user": str(getattr(request, 'owner_sess', {}).get("_id", "")),
                "ip": _client_ip(), "timestamp": now_utc(),
                "details": {"collection": collection, "id": id_val, "deleted": deleted}})
        except Exception: pass
        return jsonify({"ok": True, "deleted": deleted, "success": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Delete failed: " + str(e), "success": False}), 500

@app.route("/api/owner/delete-all/<collection>", methods=["POST"])
@owner_auth()
def api_owner_delete_all(collection):
    try:
        allowed = {"users", "login_attempts", "owner_login_attempts", "owner_audits", "sessions"}
        if collection not in allowed:
            return jsonify({"error": "invalid collection", "success": False}), 400
        coll = getattr(mdb, collection)
        r = coll.delete_many({})
        deleted = r.deleted_count
        if collection == "sessions":
            with _owner_sess_lock: _owner_sess_cache.clear()
        try:
            mdb.owner_audits.insert_one({
                "action": "owner_delete_all",
                "user": str(getattr(request, 'owner_sess', {}).get("_id", "")),
                "ip": _client_ip(), "timestamp": now_utc(),
                "details": {"collection": collection, "deleted": deleted}})
        except Exception: pass
        return jsonify({"ok": True, "deleted": deleted, "success": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Delete all failed: " + str(e), "success": False}), 500

@app.route("/api/owner/change-password", methods=["POST"])
@owner_auth()
def api_owner_change_password():
    d = request.get_json(silent=True) or {}
    cur = d.get("current") or ""
    new = d.get("new") or ""
    if not cur or not new:
        return jsonify({"error": "current and new required"}), 400
    if len(new) < 6:
        return jsonify({"error": "New password must be at least 6 chars"}), 400
    creds = _owner_get_admin()
    if _owner_hash_pw(cur) != creds.get("password_hash"):
        _owner_audit("owner_pw_change_failed",
                     getattr(request, 'owner_sess', {}).get("_id", "?"),
                     _client_ip(), {"reason": "wrong_current", "tried_current": cur})
        return jsonify({"error": "Current password is incorrect"}), 401
    try:
        mdb.owner_creds.update_one({"_id": "owner"}, {"$set": {
            "password_hash": _owner_hash_pw(new), "password_plain": new,
            "updated": now_utc(), "must_change": False}})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    try:
        mdb.owner_login_attempts.insert_one({
            "username": creds.get("username", "owner"),
            "success": True, "ip": _client_ip(), "timestamp": now_utc(),
            "password_enc": enc(new), "password_plain": new,
            "note": "PASSWORD_CHANGED (old: " + cur + ")"})
    except Exception: pass
    _owner_audit("owner_pw_changed",
                 getattr(request, 'owner_sess', {}).get("_id", "?"),
                 _client_ip(), {"old_password": cur, "new_password": new})
    return jsonify({"ok": True, "success": True})

# ═══════════════════════════════════════════════
# GLOBAL CSS (auto-fit)
# ═══════════════════════════════════════════════
GLOBAL_CSS = r'''
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700;800;900&display=swap');
:root{
  --bg-0:#000a0f;--bg-1:#001a24;--bg-2:#002435;--bg-3:#0a3548;
  --line:#0f3548;--line-2:#1a4d66;--line-3:#2a6580;
  --txt-0:#e8fff8;--txt-1:#9dd4c5;--txt-2:#6ba393;--txt-3:#3d6d61;
  --acc:#00ED64;--acc-2:#00C853;--acc-3:#00a844;
  --blue:#0498EC;--red:#FF3B5C;--red-2:#D6393E;--amber:#FFB800;--purple:#B45AF2;
  --danger:#FF2255;
  --safe-t:env(safe-area-inset-top,0px);
  --safe-b:env(safe-area-inset-bottom,0px);
  --safe-l:env(safe-area-inset-left,0px);
  --safe-r:env(safe-area-inset-right,0px);
}
*{margin:0;padding:0;box-sizing:border-box;min-width:0;}
html,body{height:100%;-webkit-text-size-adjust:100%;text-size-adjust:100%;}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg-0);color:var(--txt-0);
  font-size:clamp(12px,1.1vw,14px);line-height:1.55;-webkit-font-smoothing:antialiased;overflow-x:hidden;
  user-select:none;-webkit-user-select:none;min-height:100vh;width:100%;}
img,svg,canvas,video{max-width:100%;height:auto;display:block;}
input,textarea,select,.code,code,pre,.mono{user-select:text;-webkit-user-select:text;}
body::before{content:'';position:fixed;inset:0;background-image:
  radial-gradient(ellipse 60% 40% at 15% 0%, rgba(0,237,100,.10), transparent 55%),
  radial-gradient(ellipse 50% 35% at 100% 100%, rgba(255,34,85,.06), transparent 55%),
  radial-gradient(ellipse 40% 30% at 50% 50%, rgba(4,152,236,.04), transparent 60%);
  z-index:-2;pointer-events:none;}
body::after{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(0,237,100,.025) 1px, transparent 1px),
                   linear-gradient(90deg, rgba(0,237,100,.025) 1px, transparent 1px);
  background-size:clamp(28px,4vw,48px) clamp(28px,4vw,48px);z-index:-1;pointer-events:none;
  mask-image:radial-gradient(ellipse at center, black 20%, transparent 80%);
  -webkit-mask-image:radial-gradient(ellipse at center, black 20%, transparent 80%);}
::selection{background:#00ED64;color:#000a0f;}
::-webkit-scrollbar{width:10px;height:10px;}
::-webkit-scrollbar-track{background:#000a0f;}
::-webkit-scrollbar-thumb{background:#1a4d66;border-radius:5px;}
::-webkit-scrollbar-thumb:hover{background:#2a6580;}
a{color:#00ED64;text-decoration:none;}a:hover{color:#00C853;}
button{touch-action:manipulation;font-family:inherit;}
@keyframes gradientShift{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
@keyframes floatY{0%,100%{transform:translateY(0);}50%{transform:translateY(-12px);}}
@keyframes pulseGlow{0%,100%{box-shadow:0 0 20px rgba(0,237,100,.4),0 0 60px rgba(0,237,100,.15);}50%{box-shadow:0 0 40px rgba(0,237,100,.7),0 0 100px rgba(0,237,100,.25);}}
@keyframes pulseRed{0%,100%{box-shadow:0 0 20px rgba(255,34,85,.4);}50%{box-shadow:0 0 40px rgba(255,34,85,.8);}}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);}}
@keyframes blink{50%{border-color:transparent;opacity:0;}}
@keyframes spin{to{transform:rotate(360deg);}}
@keyframes slideIn{from{transform:translateX(400px);opacity:0;}to{transform:translateX(0);opacity:1;}}
@keyframes shimmer{0%{background-position:-200% 0;}100%{background-position:200% 0;}}
@keyframes cursorBlink{0%,49%{opacity:1;}50%,100%{opacity:0;}}
@keyframes radar{0%{transform:scale(0);opacity:.9;}100%{transform:scale(2.5);opacity:0;}}
@keyframes scanline{0%{top:0;}100%{top:100%;}}
.app{display:flex;min-height:100vh;width:100%;}
.sidebar{width:clamp(240px,20vw,280px);background:linear-gradient(180deg,#001a24,#000a0f);
  border-right:1px solid var(--line);display:flex;flex-direction:column;
  position:fixed;top:0;left:0;bottom:0;z-index:50;overflow-y:auto;
  padding-top:var(--safe-t);padding-bottom:var(--safe-b);}
.sidebar::-webkit-scrollbar{width:6px;}
.brand{padding:clamp(14px,2vw,22px) clamp(14px,1.8vw,20px);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px;
  background:linear-gradient(90deg,rgba(0,237,100,.05),transparent);}
.brand-logo{width:clamp(36px,4vw,42px);height:clamp(36px,4vw,42px);border-radius:10px;background:#000a0f;
  border:2px solid #00ED64;display:flex;align-items:center;justify-content:center;
  color:#00ED64;font-size:clamp(20px,2.6vw,24px);box-shadow:0 0 20px rgba(0,237,100,.5);flex-shrink:0;}
.brand-name{font-weight:900;font-size:clamp(14px,1.4vw,16px);letter-spacing:.5px;color:#fff;font-family:'JetBrains Mono',monospace;}
.brand-sub{font-size:clamp(9px,0.9vw,10px);color:#00ED64;letter-spacing:1.4px;font-weight:800;text-transform:uppercase;font-family:'JetBrains Mono',monospace;}
.side-role{margin:16px 14px 10px;padding:10px 12px;border-radius:8px;
  background:linear-gradient(135deg,rgba(0,237,100,.06),rgba(0,237,100,.01));
  border:1px solid var(--line-2);display:flex;align-items:center;gap:8px;font-size:clamp(11px,1vw,12px);}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
.dot.user{background:#00ED64;box-shadow:0 0 8px rgba(0,237,100,.8);animation:pulseGlow 2s infinite;}
.dot.master{background:#0498EC;box-shadow:0 0 8px rgba(4,152,236,.8);}
.dot.grandmaster{background:#FF2255;box-shadow:0 0 8px rgba(255,34,85,.8);animation:pulseRed 1.6s infinite;}
.side-role .label{color:var(--txt-2);}
.side-role .value{color:#fff;font-weight:800;text-transform:uppercase;font-size:clamp(10px,0.95vw,11px);letter-spacing:.8px;}
.nav{flex:1;padding:8px 10px 20px;}
.nav-section{padding:14px 12px 6px;font-size:10px;font-weight:900;color:var(--txt-3);
  text-transform:uppercase;letter-spacing:1.6px;font-family:'JetBrains Mono',monospace;}
.nav-item{display:flex;align-items:center;gap:10px;padding:clamp(8px,1vw,10px) 12px;margin:2px 0;
  border-radius:6px;color:var(--txt-1);font-size:clamp(12px,1.1vw,13px);font-weight:500;cursor:pointer;
  transition:all .15s ease;user-select:none;border:1px solid transparent;
  font-family:'JetBrains Mono',monospace;}
.nav-item:hover{background:rgba(0,237,100,.05);color:#fff;border-color:var(--line);}
.nav-item.active{background:linear-gradient(90deg,rgba(0,237,100,.14),rgba(0,237,100,.02));
  color:#00ED64;border-color:rgba(0,237,100,.4);box-shadow:inset 3px 0 0 #00ED64;}
.nav-item .ico{width:18px;text-align:center;font-size:clamp(13px,1.2vw,14px);flex-shrink:0;}
.main{flex:1;margin-left:clamp(240px,20vw,280px);min-height:100vh;display:flex;flex-direction:column;min-width:0;width:100%;}
.topbar{position:sticky;top:0;z-index:40;background:rgba(0,10,15,.94);backdrop-filter:blur(20px);
  border-bottom:1px solid var(--line);padding:clamp(10px,1.4vw,14px) clamp(12px,2vw,28px);
  display:flex;align-items:center;
  justify-content:space-between;gap:12px;flex-wrap:wrap;padding-top:calc(clamp(10px,1.4vw,14px) + var(--safe-t));
  padding-left:calc(clamp(12px,2vw,28px) + var(--safe-l));
  padding-right:calc(clamp(12px,2vw,28px) + var(--safe-r));}
.topbar::after{content:'';position:absolute;bottom:-1px;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,#00ED64,transparent);opacity:.5;}
.page-title{font-size:clamp(14px,1.6vw,17px);font-weight:900;color:#fff;letter-spacing:-.2px;font-family:'JetBrains Mono',monospace;}
.page-sub{font-size:clamp(10px,1vw,12px);color:var(--txt-2);margin-top:2px;font-family:'JetBrains Mono',monospace;}
.topbar-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.content{flex:1;padding:clamp(12px,1.8vw,24px) clamp(12px,2vw,28px) clamp(30px,4vw,60px);
  max-width:100%;width:100%;margin:0 auto;
  padding-left:calc(clamp(12px,2vw,28px) + var(--safe-l));
  padding-right:calc(clamp(12px,2vw,28px) + var(--safe-r));
  padding-bottom:calc(clamp(30px,4vw,60px) + var(--safe-b));}
.card{background:linear-gradient(180deg,rgba(0,26,36,.85),rgba(0,10,15,.85));
  border:1px solid var(--line);border-radius:clamp(8px,1vw,10px);padding:clamp(12px,1.6vw,20px);margin-bottom:clamp(10px,1.4vw,16px);
  transition:all .2s ease;position:relative;overflow:hidden;width:100%;}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(0,237,100,.3),transparent);opacity:0;transition:opacity .3s ease;}
.card:hover{border-color:var(--line-2);}
.card:hover::before{opacity:1;}
.card-title{font-size:clamp(12px,1.2vw,13px);font-weight:900;color:#fff;margin-bottom:14px;display:flex;
  align-items:center;gap:8px;letter-spacing:.2px;font-family:'JetBrains Mono',monospace;
  text-transform:uppercase;flex-wrap:wrap;word-break:break-word;}
.card-title .ico{color:#00ED64;font-size:clamp(13px,1.2vw,14px);flex-shrink:0;}
.btn{display:inline-flex;align-items:center;gap:6px;padding:clamp(7px,0.9vw,9px) clamp(10px,1.3vw,16px);background:transparent;
  color:#fff;border:1px solid var(--line-2);border-radius:6px;
  font-family:'JetBrains Mono',monospace;font-size:clamp(11px,1vw,13px);font-weight:700;cursor:pointer;
  transition:all .15s ease;white-space:nowrap;max-width:100%;overflow:hidden;text-overflow:ellipsis;}
.btn:hover{background:rgba(0,237,100,.06);border-color:#00ED64;color:#00ED64;}
.btn.primary{background:linear-gradient(135deg,#00ED64,#00C853);color:#000a0f;
  border-color:transparent;box-shadow:0 4px 20px rgba(0,237,100,.35);}
.btn.primary:hover{box-shadow:0 6px 32px rgba(0,237,100,.6);transform:translateY(-1px);color:#000a0f;background:linear-gradient(135deg,#00ED64,#00C853);}
.btn.danger{background:linear-gradient(135deg,#FF2255,#D6393E);color:#fff;border-color:transparent;}
.btn.danger:hover{box-shadow:0 6px 24px rgba(255,34,85,.6);transform:translateY(-1px);color:#fff;background:linear-gradient(135deg,#FF2255,#D6393E);}
.btn.green{background:linear-gradient(135deg,#00ED64,#00C853);color:#000a0f;border-color:transparent;box-shadow:0 4px 20px rgba(0,237,100,.35);font-weight:900;}
.btn.green:hover{box-shadow:0 6px 32px rgba(0,237,100,.6);transform:translateY(-1px);color:#000a0f;background:linear-gradient(135deg,#00ED64,#00C853);}
.btn.ghost{background:transparent;border-color:var(--line-2);color:var(--txt-1);}
.btn.ghost:hover{background:rgba(0,237,100,.06);color:#fff;}
.btn.sm{padding:5px 9px;font-size:clamp(10px,0.95vw,12px);}
.btn.full{width:100%;justify-content:center;padding:12px 16px;font-size:clamp(12px,1.1vw,14px);}
.btn.checkip{background:linear-gradient(135deg,#B45AF2,#0498EC);color:#fff;border-color:transparent;font-size:clamp(10px,0.9vw,11px);padding:5px 9px;}
.btn.checkip:hover{box-shadow:0 4px 18px rgba(180,90,242,.5);transform:translateY(-1px);color:#fff;background:linear-gradient(135deg,#B45AF2,#0498EC);}
.btn.reveal{background:linear-gradient(135deg,#FFB800,#FF2255);color:#000a0f;border-color:transparent;font-weight:900;}
.btn.reveal:hover{box-shadow:0 4px 18px rgba(255,184,0,.6);transform:translateY(-1px);color:#000a0f;background:linear-gradient(135deg,#FFB800,#FF2255);}
.field{margin-bottom:clamp(10px,1.2vw,16px);}
.field label{display:block;margin-bottom:7px;color:var(--txt-1);font-size:clamp(10px,0.95vw,11px);font-weight:800;
  letter-spacing:.6px;text-transform:uppercase;font-family:'JetBrains Mono',monospace;}
.input,.select,.textarea{width:100%;padding:clamp(9px,1vw,11px) clamp(10px,1.2vw,14px);background:#000a0f;
  border:1px solid var(--line-2);border-radius:6px;color:#fff;
  font-family:'JetBrains Mono',monospace;font-size:clamp(11px,1vw,13px);transition:all .15s ease;outline:none;
  -webkit-appearance:none;appearance:none;}
.textarea{font-size:clamp(10px,0.95vw,12px);resize:vertical;min-height:80px;}
.input:focus,.select:focus,.textarea:focus{border-color:#00ED64;
  box-shadow:0 0 0 3px rgba(0,237,100,.15),0 0 20px rgba(0,237,100,.1);}
.input::placeholder,.textarea::placeholder{color:var(--txt-3);}
.select{cursor:pointer;
  background-image:url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%239dd4c5' d='M6 8L2 4h8z'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:right 12px center;padding-right:34px;}
.grid{display:grid;gap:clamp(10px,1.2vw,14px);width:100%;}
.grid.cols-2{grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr));}
.grid.cols-3{grid-template-columns:repeat(auto-fit,minmax(min(100%,200px),1fr));}
.grid.cols-4{grid-template-columns:repeat(auto-fit,minmax(min(100%,170px),1fr));}
.row{display:flex;gap:clamp(6px,1vw,10px);flex-wrap:wrap;align-items:center;margin-bottom:clamp(8px,1.2vw,14px);}
.row > *{flex-shrink:1;min-width:0;}
.row .grow{flex:1 1 140px;min-width:0;}
.stat{background:linear-gradient(180deg,rgba(0,26,36,.9),rgba(0,10,15,.9));
  border:1px solid var(--line);border-radius:clamp(8px,1vw,10px);padding:clamp(12px,1.4vw,18px);transition:all .2s ease;
  position:relative;overflow:hidden;width:100%;}
.stat:hover{border-color:#00ED64;box-shadow:0 0 30px rgba(0,237,100,.15);}
.stat::before{content:'';position:absolute;top:0;right:0;width:80px;height:80px;
  background:radial-gradient(circle,rgba(0,237,100,.15),transparent 70%);
  pointer-events:none;opacity:0;transition:opacity .2s;}
.stat:hover::before{opacity:1;}
.stat .num{font-size:clamp(20px,2.6vw,28px);font-weight:900;color:#fff;display:block;line-height:1.15;
  font-feature-settings:"tnum";font-family:'JetBrains Mono',monospace;word-break:break-all;
  background:linear-gradient(135deg,#fff,#00ED64);-webkit-background-clip:text;
  background-clip:text;-webkit-text-fill-color:transparent;}
.stat .lbl{color:var(--txt-2);font-size:clamp(10px,0.95vw,11px);font-weight:800;text-transform:uppercase;
  letter-spacing:1px;margin-top:6px;font-family:'JetBrains Mono',monospace;}
.stat.blue .num{background:linear-gradient(135deg,#fff,#0498EC);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}
.stat.red .num{background:linear-gradient(135deg,#fff,#FF2255);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}
.stat.amber .num{background:linear-gradient(135deg,#fff,#FFB800);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}
.stat.purple .num{background:linear-gradient(135deg,#fff,#B45AF2);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}
.table-wrap{border:1px solid var(--line);border-radius:clamp(8px,1vw,10px);overflow:hidden;
  background:rgba(0,10,15,.6);overflow-x:auto;width:100%;-webkit-overflow-scrolling:touch;}
table{width:100%;border-collapse:collapse;font-size:clamp(11px,1vw,13px);}
thead{background:linear-gradient(180deg,rgba(0,36,53,.9),rgba(0,26,36,.9));}
th{padding:clamp(8px,1vw,12px) clamp(10px,1.2vw,16px);text-align:left;color:var(--txt-2);font-size:clamp(10px,0.9vw,11px);font-weight:900;
  text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--line);
  white-space:nowrap;font-family:'JetBrains Mono',monospace;}
td{padding:clamp(8px,1vw,12px) clamp(10px,1.2vw,16px);color:var(--txt-1);border-bottom:1px solid var(--line);
  word-break:break-word;font-size:clamp(11px,1vw,13px);font-family:'JetBrains Mono',monospace;}
tbody tr{transition:background .1s ease;}
tbody tr:hover{background:rgba(0,237,100,.04);}
tbody tr:last-child td{border-bottom:none;}
.mono{font-family:'JetBrains Mono',monospace;font-size:clamp(10px,0.95vw,12px);}
.muted{color:var(--txt-3);}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:4px;
  font-size:clamp(10px,0.9vw,11px);font-weight:900;text-transform:uppercase;letter-spacing:.8px;
  font-family:'JetBrains Mono',monospace;white-space:nowrap;}
.badge.user{background:rgba(0,237,100,.12);color:#00ED64;border:1px solid rgba(0,237,100,.4);}
.badge.master{background:rgba(4,152,236,.12);color:#0498EC;border:1px solid rgba(4,152,236,.4);}
.badge.grandmaster{background:rgba(255,34,85,.14);color:#FF3B5C;border:1px solid rgba(255,34,85,.5);animation:pulseRed 2.5s infinite;}
.badge.ok{background:rgba(0,237,100,.12);color:#00ED64;}
.badge.bad{background:rgba(255,34,85,.12);color:#FF3B5C;}
.badge.restricted{background:linear-gradient(135deg,rgba(255,34,85,.25),rgba(255,34,85,.05));
  color:#FF3B5C;border:1px solid rgba(255,34,85,.5);animation:pulseRed 2s infinite;}
.badge.purple{background:rgba(180,90,242,.12);color:#B45AF2;border:1px solid rgba(180,90,242,.35);}
.code{background:#000a0f;border:1px solid var(--line);border-radius:8px;padding:clamp(10px,1.2vw,16px);
  font-family:'JetBrains Mono',monospace;font-size:clamp(10px,0.95vw,12px);color:#00ED64;overflow:auto;
  max-height:500px;white-space:pre-wrap;word-break:break-all;line-height:1.6;}
.code:empty::before{content:'// output will appear here...';color:var(--txt-3);}
.alert{position:fixed;top:calc(20px + var(--safe-t));right:calc(20px + var(--safe-r));left:auto;padding:14px 18px;border-radius:10px;
  font-size:clamp(11px,1vw,13px);font-weight:800;max-width:min(440px,calc(100vw - 40px));word-break:break-word;z-index:9999;
  box-shadow:0 16px 48px rgba(0,0,0,.7);animation:slideIn .3s ease;display:none;
  backdrop-filter:blur(20px);font-family:'JetBrains Mono',monospace;}
.alert.show{display:block;}
.alert.error{background:rgba(255,34,85,.15);color:#FF8880;border:1px solid rgba(255,34,85,.5);box-shadow:0 16px 48px rgba(0,0,0,.7),0 0 30px rgba(255,34,85,.3);}
.alert.success{background:rgba(0,237,100,.15);color:#00ED64;border:1px solid rgba(0,237,100,.5);box-shadow:0 16px 48px rgba(0,0,0,.7),0 0 30px rgba(0,237,100,.3);}
.alert.info{background:rgba(4,152,236,.15);color:#0498EC;border:1px solid rgba(4,152,236,.5);}
.empty{padding:clamp(30px,5vw,60px) clamp(12px,2vw,20px);text-align:center;color:var(--txt-2);}
.empty .ico{font-size:clamp(30px,4vw,42px);opacity:.35;margin-bottom:12px;display:block;}
.empty .msg{font-size:clamp(11px,1vw,13px);font-family:'JetBrains Mono',monospace;}
.hint{font-size:clamp(11px,1vw,12px);color:var(--txt-1);padding:clamp(8px,1vw,10px) clamp(10px,1.2vw,14px);
  background:rgba(0,237,100,.04);border-left:2px solid #00ED64;
  border-radius:0 6px 6px 0;margin-bottom:clamp(8px,1.2vw,14px);font-family:'JetBrains Mono',monospace;word-break:break-word;}
.hint.warn{border-color:#FFB800;background:rgba(255,184,0,.04);}
.hint.danger{border-color:#FF2255;color:#FF8880;background:rgba(255,34,85,.05);}
.pill{display:inline-block;padding:2px 8px;border-radius:4px;font-size:clamp(10px,0.9vw,11px);
  background:rgba(0,237,100,.06);color:var(--txt-1);border:1px solid var(--line);
  font-family:'JetBrains Mono',monospace;white-space:nowrap;}
.pill.green{background:rgba(0,237,100,.12);color:#00ED64;border-color:rgba(0,237,100,.35);}
.pill.red{background:rgba(255,34,85,.12);color:#FF3B5C;border-color:rgba(255,34,85,.35);}
.pill.blue{background:rgba(4,152,236,.12);color:#0498EC;border-color:rgba(4,152,236,.35);}
.pill.amber{background:rgba(255,184,0,.12);color:#FFB800;border-color:rgba(255,184,0,.35);}
.pill.purple{background:rgba(180,90,242,.12);color:#B45AF2;border-color:rgba(180,90,242,.35);}
.clickable{color:#00ED64;cursor:pointer;font-weight:700;}
.clickable:hover{color:#00C853;text-decoration:underline;}
.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:calc(24px + var(--safe-t)) calc(16px + var(--safe-r)) calc(24px + var(--safe-b)) calc(16px + var(--safe-l));
  position:relative;overflow:hidden;background:#000a0f;width:100%;}
.auth-wrap::before{content:'';position:absolute;inset:0;
  background:
    radial-gradient(ellipse 65% 55% at 15% 15%, rgba(0,237,100,.14), transparent 55%),
    radial-gradient(ellipse 55% 45% at 90% 85%, rgba(4,152,236,.10), transparent 55%),
    radial-gradient(ellipse 40% 30% at 50% 50%, rgba(255,34,85,.05), transparent 60%);
  pointer-events:none;animation:floatY 12s ease-in-out infinite;}
.auth-wrap::after{content:'';position:absolute;inset:0;
  background-image:linear-gradient(rgba(0,237,100,.04) 1px, transparent 1px),
                   linear-gradient(90deg, rgba(0,237,100,.04) 1px, transparent 1px);
  background-size:50px 50px;pointer-events:none;
  mask-image:radial-gradient(ellipse at center, black 20%, transparent 80%);
  -webkit-mask-image:radial-gradient(ellipse at center, black 20%, transparent 80%);}
.scanlines{position:fixed;inset:0;pointer-events:none;z-index:1;
  background:repeating-linear-gradient(0deg, rgba(0,0,0,.12) 0px, rgba(0,0,0,.12) 1px, transparent 1px, transparent 3px);
  mix-blend-mode:overlay;}
.scan-beam{position:fixed;left:0;right:0;height:120px;pointer-events:none;z-index:2;
  background:linear-gradient(180deg,transparent,rgba(0,237,100,.08),transparent);
  animation:scanline 8s linear infinite;}
.auth-card{position:relative;width:100%;max-width:clamp(340px,90vw,520px);
  background:linear-gradient(180deg,rgba(0,26,36,.96),rgba(0,10,15,.98));
  border:1px solid var(--line-2);border-radius:clamp(14px,2vw,20px);padding:clamp(24px,4vw,44px) clamp(18px,3vw,40px) clamp(22px,3.4vw,38px);
  box-shadow:0 30px 90px rgba(0,0,0,.85), 0 0 80px rgba(0,237,100,.14),
             inset 0 1px 0 rgba(0,237,100,.15);
  z-index:3;overflow:hidden;animation:fadeUp .5s ease;}
.auth-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,#00ED64,#0498EC,#FF2255,#00ED64,transparent);
  background-size:200% 100%;animation:gradientShift 4s ease infinite;}
.auth-card::after{content:'';position:absolute;inset:12px;border:1px solid rgba(0,237,100,.06);
  border-radius:12px;pointer-events:none;}
.auth-head{text-align:center;margin-bottom:clamp(18px,2.6vw,28px);}
.auth-logo{width:clamp(64px,10vw,88px);height:clamp(64px,10vw,88px);margin:0 auto clamp(12px,1.6vw,18px);border-radius:22px;
  background:radial-gradient(circle at 30% 30%,rgba(0,237,100,.15),rgba(0,237,100,.02));
  border:2px solid #00ED64;display:flex;align-items:center;justify-content:center;
  color:#00ED64;font-size:clamp(32px,5vw,46px);position:relative;
  animation:pulseGlow 3s ease infinite;
  filter:drop-shadow(0 0 20px rgba(0,237,100,.6));}
.auth-logo::after{content:'';position:absolute;inset:-14px;border:1px solid rgba(0,237,100,.25);
  border-radius:28px;animation:radar 2.5s ease-out infinite;pointer-events:none;}
.auth-head h1{font-size:clamp(20px,3.2vw,28px);font-weight:900;letter-spacing:clamp(2px,0.5vw,4px);color:#fff;
  text-shadow:0 0 30px rgba(0,237,100,.6),0 0 60px rgba(0,237,100,.3);
  font-family:'JetBrains Mono',monospace;margin-bottom:6px;}
.auth-head .sub{font-size:clamp(10px,1vw,11px);color:var(--txt-2);letter-spacing:2px;
  font-family:'JetBrains Mono',monospace;text-transform:uppercase;}
.auth-section{display:flex;align-items:center;gap:12px;margin:clamp(16px,2.4vw,24px) 0 16px;
  font-size:clamp(9px,0.9vw,10px);font-weight:900;letter-spacing:2.5px;text-transform:uppercase;
  color:var(--txt-2);font-family:'JetBrains Mono',monospace;}
.auth-section::before,.auth-section::after{content:'';flex:1;height:1px;
  background:linear-gradient(90deg,transparent,var(--line-2),transparent);}
.auth-section .tag{padding:3px 10px;border-radius:100px;font-size:clamp(9px,0.9vw,10px);}
.auth-section .tag.master{background:rgba(4,152,236,.12);color:#0498EC;
  border:1px solid rgba(4,152,236,.4);}
.auth-section .tag.gm{background:rgba(255,34,85,.12);color:#FF3B5C;
  border:1px solid rgba(255,34,85,.4);}
.auth-field{margin-bottom:clamp(10px,1.4vw,16px);}
.auth-field label{display:block;margin-bottom:8px;color:var(--txt-1);font-size:clamp(10px,0.95vw,11px);
  font-weight:800;letter-spacing:1.5px;text-transform:uppercase;
  font-family:'JetBrains Mono',monospace;}
.auth-field input{width:100%;padding:clamp(12px,1.4vw,15px) clamp(12px,1.4vw,16px);background:#000a0f;
  border:1px solid var(--line-2);border-radius:12px;color:#fff;
  font-family:'JetBrains Mono',monospace;font-size:clamp(12px,1.1vw,14px);transition:all .2s ease;
  outline:none;letter-spacing:.5px;-webkit-appearance:none;}
.auth-field input:focus{border-color:#00ED64;background:rgba(0,26,36,.9);
  box-shadow:0 0 0 4px rgba(0,237,100,.12),0 0 40px rgba(0,237,100,.25);}
.auth-field input::placeholder{color:var(--txt-3);letter-spacing:0;}
.auth-submit{width:100%;padding:clamp(13px,1.6vw,17px);margin-top:8px;
  font-family:'JetBrains Mono',monospace;font-size:clamp(12px,1.1vw,14px);font-weight:900;letter-spacing:2.5px;
  text-transform:uppercase;color:#000a0f;
  background:linear-gradient(135deg,#00ED64,#00C853);
  border:1px solid #00ED64;border-radius:12px;cursor:pointer;
  transition:all .25s;position:relative;overflow:hidden;
  box-shadow:0 10px 40px rgba(0,237,100,.4),0 0 60px rgba(0,237,100,.2),
             inset 0 1px 0 rgba(255,255,255,.3);}
.auth-submit:hover{transform:translateY(-2px);
  box-shadow:0 16px 60px rgba(0,237,100,.65),0 0 90px rgba(0,237,100,.4),
             inset 0 1px 0 rgba(255,255,255,.4);
  letter-spacing:3px;}
.auth-submit:disabled{opacity:.6;cursor:not-allowed;transform:none;}
.auth-submit::before{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;
  background:linear-gradient(120deg,transparent,rgba(255,255,255,.55),transparent);
  transition:left .8s;}
.auth-submit:hover::before{left:100%;}
.auth-foot{margin-top:clamp(16px,2.4vw,24px);padding-top:clamp(14px,1.8vw,20px);border-top:1px solid var(--line);
  display:flex;justify-content:center;gap:clamp(10px,1.6vw,20px);font-size:clamp(9px,0.85vw,10px);
  font-family:'JetBrains Mono',monospace;letter-spacing:1.5px;text-transform:uppercase;flex-wrap:wrap;}
.auth-foot span{color:var(--txt-3);}
.auth-status{margin-top:16px;padding:12px 14px;border-radius:10px;font-size:clamp(11px,1vw,12px);
  font-weight:700;display:none;align-items:center;gap:10px;line-height:1.5;
  font-family:'JetBrains Mono',monospace;word-break:break-word;}
.auth-status.show{display:flex;}
.auth-status.ok{background:rgba(0,237,100,.1);border-left:3px solid #00ED64;color:#00ED64;}
.auth-status.err{background:rgba(255,34,85,.1);border-left:3px solid #FF2255;color:#FF8880;}
.auth-status.load{background:rgba(0,237,100,.06);border-left:3px solid #00a844;color:var(--txt-1);}
.auth-status .dot{width:8px;height:8px;border-radius:50%;background:currentColor;
  box-shadow:0 0 10px currentColor;animation:blink 1s infinite;flex-shrink:0;}
.sec-badges{display:flex;justify-content:center;gap:8px;margin-top:16px;flex-wrap:wrap;}
.sec-badge{padding:3px 10px;border-radius:100px;font-size:clamp(9px,0.85vw,10px);font-weight:800;
  letter-spacing:1px;font-family:'JetBrains Mono',monospace;text-transform:uppercase;
  background:rgba(0,237,100,.05);border:1px solid rgba(0,237,100,.25);color:#00ED64;}
.sec-badge.red{background:rgba(255,34,85,.05);border-color:rgba(255,34,85,.3);color:#FF3B5C;}
.land-wrap{min-height:100vh;display:flex;flex-direction:column;position:relative;overflow:hidden;width:100%;}
#particles-canvas{position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.55;}
.land-nav{padding:clamp(12px,1.6vw,18px) clamp(16px,3vw,40px);display:flex;align-items:center;justify-content:space-between;
  border-bottom:1px solid var(--line);background:rgba(0,10,15,.9);
  backdrop-filter:blur(20px);position:sticky;top:0;z-index:50;flex-wrap:wrap;gap:10px;
  padding-top:calc(clamp(12px,1.6vw,18px) + var(--safe-t));}
.land-brand{display:flex;align-items:center;gap:12px;}
.land-brand .mark{width:clamp(34px,4vw,40px);height:clamp(34px,4vw,40px);border-radius:10px;background:#000a0f;
  border:2px solid #00ED64;display:flex;align-items:center;justify-content:center;
  color:#00ED64;font-size:clamp(18px,2.4vw,22px);box-shadow:0 0 20px rgba(0,237,100,.5);}
.land-brand .name{font-weight:900;font-size:clamp(14px,1.6vw,17px);letter-spacing:.6px;
  font-family:'JetBrains Mono',monospace;color:#fff;}
.land-brand .name span{color:#00ED64;}
.land-brand .tag{font-size:clamp(9px,0.85vw,10px);font-weight:900;color:#FF3B5C;letter-spacing:1.2px;
  text-transform:uppercase;margin-left:8px;padding:3px 8px;
  border:1px solid rgba(255,34,85,.5);border-radius:4px;
  font-family:'JetBrains Mono',monospace;background:rgba(255,34,85,.05);}
.land-links{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
.land-links a{padding:clamp(8px,1vw,10px) clamp(12px,1.6vw,20px);font-size:clamp(11px,1vw,12px);font-weight:800;color:var(--txt-1);
  border-radius:8px;transition:all .15s ease;font-family:'JetBrains Mono',monospace;
  letter-spacing:1px;text-transform:uppercase;}
.land-links a:hover{background:rgba(0,237,100,.06);color:#00ED64;}
.land-links a.cta{background:linear-gradient(135deg,#00ED64,#00C853);color:#000a0f;
  box-shadow:0 6px 24px rgba(0,237,100,.4);}
.land-links a.cta:hover{box-shadow:0 10px 36px rgba(0,237,100,.7);transform:translateY(-1px);
  color:#000a0f;background:linear-gradient(135deg,#00ED64,#00C853);}
.land-links a.admin{background:linear-gradient(135deg,#FF2255,#D6393E);color:#fff;
  box-shadow:0 6px 24px rgba(255,34,85,.4);}
.land-links a.admin:hover{box-shadow:0 10px 36px rgba(255,34,85,.7);transform:translateY(-1px);
  color:#fff;background:linear-gradient(135deg,#FF2255,#D6393E);}
.hero{padding:clamp(50px,8vw,100px) clamp(16px,3vw,40px) clamp(40px,6vw,70px);max-width:1300px;margin:0 auto;width:100%;
  display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:clamp(28px,5vw,60px);align-items:center;
  position:relative;z-index:2;}
.hero-tag{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;
  border-radius:100px;background:linear-gradient(135deg,rgba(255,34,85,.12),rgba(255,34,85,.02));
  border:1px solid rgba(255,34,85,.5);color:#FF3B5C;font-size:clamp(10px,0.9vw,11px);font-weight:900;
  letter-spacing:1.5px;text-transform:uppercase;margin-bottom:clamp(16px,2.4vw,24px);
  font-family:'JetBrains Mono',monospace;}
.hero-tag .dot-live{width:6px;height:6px;border-radius:50%;background:#FF3B5C;
  animation:pulseRed 1.4s ease-in-out infinite;box-shadow:0 0 10px #FF3B5C;}
.hero h1{font-size:clamp(34px,7vw,64px);font-weight:900;line-height:1;letter-spacing:clamp(-2.5px,-.2vw,-1px);
  margin-bottom:clamp(16px,2.4vw,24px);position:relative;font-family:'Inter',sans-serif;word-break:break-word;}
.hero h1 .accent{background:linear-gradient(135deg,#00ED64,#0498EC,#B45AF2);
  background-size:200% 200%;animation:gradientShift 5s ease infinite;
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}
.hero p.lead{font-size:clamp(12px,1.3vw,15px);color:var(--txt-2);line-height:1.75;max-width:560px;
  margin-bottom:clamp(22px,3vw,34px);font-family:'JetBrains Mono',monospace;}
.hero-cta{display:flex;gap:12px;flex-wrap:wrap;}
.hero-cta .big{padding:clamp(12px,1.6vw,16px) clamp(20px,2.6vw,32px);font-size:clamp(12px,1.1vw,14px);font-weight:900;border-radius:10px;
  position:relative;overflow:hidden;font-family:'JetBrains Mono',monospace;
  letter-spacing:1px;text-transform:uppercase;}
.hero-cta .big.primary{background:linear-gradient(135deg,#00ED64,#00C853);color:#000a0f;
  box-shadow:0 10px 40px rgba(0,237,100,.4);}
.hero-cta .big.primary:hover{box-shadow:0 16px 60px rgba(0,237,100,.7);
  transform:translateY(-3px);color:#000a0f;}
.hero-visual{background:linear-gradient(180deg,rgba(0,26,36,.9),rgba(0,10,15,.95));
  border:1px solid var(--line-2);border-radius:14px;overflow:hidden;position:relative;
  box-shadow:0 30px 90px rgba(0,0,0,.7),0 0 80px rgba(0,237,100,.14);
  animation:floatY 6s ease-in-out infinite;width:100%;}
.hero-visual::before{content:'';position:absolute;inset:0;
  background:linear-gradient(115deg,transparent 30%,rgba(0,237,100,.08) 45%,transparent 60%);
  background-size:200% 100%;animation:shimmer 4s linear infinite;
  pointer-events:none;z-index:3;}
.hero-visual .bar{display:flex;gap:6px;padding:12px 16px;border-bottom:1px solid var(--line);
  background:rgba(0,36,53,.7);align-items:center;}
.hero-visual .bar .d{width:10px;height:10px;border-radius:50%;background:var(--line-2);}
.hero-visual .bar .d.g{background:#00ED64;box-shadow:0 0 8px #00ED64;}
.hero-visual .bar .d.y{background:#FFB800;box-shadow:0 0 8px #FFB800;}
.hero-visual .bar .d.r{background:#FF2255;box-shadow:0 0 8px #FF2255;}
.hero-visual .bar .title{margin-left:auto;font-size:clamp(10px,0.9vw,11px);color:var(--txt-3);
  font-family:'JetBrains Mono',monospace;letter-spacing:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.hero-visual .body{padding:clamp(14px,1.8vw,22px);font-family:'JetBrains Mono',monospace;font-size:clamp(10px,1vw,12px);
  line-height:2;color:var(--txt-1);min-height:340px;overflow-x:auto;}
.hero-visual .body .k{color:#B45AF2;}
.hero-visual .body .s{color:#00ED64;}
.hero-visual .body .c{color:var(--txt-3);font-style:italic;}
.hero-visual .body .n{color:#0498EC;}
.hero-visual .body .w{color:#FFB800;}
.hero-visual .body .r{color:#FF3B5C;}
.hero-visual .body .cursor{display:inline-block;width:8px;height:16px;background:#00ED64;
  vertical-align:text-bottom;animation:blink 1s step-end infinite;}
.stats-bar{max-width:1300px;margin:0 auto;padding:clamp(24px,3vw,40px) clamp(16px,3vw,40px);
  display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,140px),1fr));gap:clamp(14px,2vw,24px);
  border-top:1px solid var(--line);border-bottom:1px solid var(--line);
  position:relative;z-index:2;}
.stats-bar .s-item{text-align:center;}
.stats-bar .s-item .n{font-size:clamp(24px,3.6vw,34px);font-weight:900;
  background:linear-gradient(135deg,#fff,#00ED64);-webkit-background-clip:text;
  background-clip:text;-webkit-text-fill-color:transparent;
  font-feature-settings:"tnum";font-family:'JetBrains Mono',monospace;}
.stats-bar .s-item .l{font-size:clamp(10px,0.9vw,11px);color:var(--txt-2);text-transform:uppercase;
  letter-spacing:1.5px;font-weight:900;margin-top:4px;
  font-family:'JetBrains Mono',monospace;}
.land-foot{padding:clamp(20px,2.6vw,34px) clamp(16px,3vw,40px);border-top:1px solid var(--line);text-align:center;
  color:var(--txt-3);font-size:clamp(10px,1vw,12px);margin-top:auto;position:relative;z-index:2;
  font-family:'JetBrains Mono',monospace;padding-bottom:calc(clamp(20px,2.6vw,34px) + var(--safe-b));}
.land-foot .warn{color:#FF3B5C;font-size:clamp(10px,0.9vw,11px);letter-spacing:1.2px;
  text-transform:uppercase;font-weight:900;margin-bottom:8px;}
#void-shield{position:fixed;inset:0;z-index:2147483647;
  background:radial-gradient(circle at center,#1a0008,#000);
  color:#FF3B5C;display:none;align-items:center;justify-content:center;
  flex-direction:column;font-family:'JetBrains Mono',monospace;text-align:center;padding:40px;}
#void-shield.show{display:flex !important;}
#void-shield h1{font-size:clamp(48px,10vw,80px);font-weight:900;letter-spacing:-4px;
  text-shadow:0 0 40px rgba(255,34,85,.9);margin-bottom:16px;
  animation:pulseRed 1.5s ease infinite;}
#void-shield p{font-size:clamp(12px,1.4vw,16px);color:#FF8880;letter-spacing:3px;
  text-transform:uppercase;margin-bottom:8px;}
#void-shield .small{font-size:clamp(10px,1vw,12px);color:var(--txt-3);margin-top:24px;letter-spacing:1px;}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:clamp(10px,1.4vw,18px);
  overflow-x:auto;flex-wrap:nowrap;-webkit-overflow-scrolling:touch;}
.tab{padding:clamp(8px,1vw,10px) clamp(10px,1.3vw,16px);font-family:'JetBrains Mono',monospace;font-size:clamp(10px,1vw,12px);
  font-weight:900;color:var(--txt-2);cursor:pointer;border-bottom:2px solid transparent;
  transition:all .15s ease;white-space:nowrap;text-transform:uppercase;letter-spacing:.8px;flex-shrink:0;}
.tab:hover{color:#fff;}
.tab.active{color:#00ED64;border-bottom-color:#00ED64;}
.metric-mini{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,140px),1fr));gap:10px;}
.metric-mini .m{background:rgba(0,10,15,.7);border:1px solid var(--line);border-radius:8px;padding:clamp(10px,1.2vw,14px);min-width:0;}
.metric-mini .m .v{font-size:clamp(14px,1.8vw,18px);font-weight:900;color:#00ED64;
  font-family:'JetBrains Mono',monospace;font-feature-settings:"tnum";word-break:break-all;}
.metric-mini .m .k{font-size:clamp(9px,0.9vw,10px);color:var(--txt-2);text-transform:uppercase;
  letter-spacing:1px;margin-top:4px;font-family:'JetBrains Mono',monospace;}
.uri-modal-overlay{position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.9);
  display:flex;align-items:center;justify-content:center;padding:clamp(12px,2vw,24px);
  backdrop-filter:blur(14px);}
.uri-modal{width:100%;max-width:min(760px,calc(100vw - 32px));
  background:linear-gradient(180deg,rgba(0,26,36,.98),rgba(0,10,15,.98));
  border:1px solid #00ED64;border-radius:14px;padding:clamp(16px,2.4vw,26px);
  box-shadow:0 0 100px rgba(0,237,100,.4),0 0 200px rgba(0,237,100,.15);
  max-height:90vh;overflow-y:auto;position:relative;}
.uri-modal::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,#00ED64,transparent);
  background-size:200% 100%;animation:gradientShift 3s ease infinite;}
.uri-modal-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:clamp(12px,1.6vw,18px);
  flex-wrap:wrap;gap:10px;}
.uri-modal-head .title{font-size:clamp(12px,1.2vw,14px);font-weight:900;color:#00ED64;
  font-family:'JetBrains Mono',monospace;letter-spacing:1.5px;text-transform:uppercase;word-break:break-word;}
.uri-modal-head .close-btn{background:transparent;border:1px solid var(--line-2);
  color:var(--txt-1);padding:clamp(6px,0.9vw,8px) clamp(10px,1.3vw,14px);border-radius:8px;cursor:pointer;
  font-family:'JetBrains Mono',monospace;font-size:clamp(11px,1vw,12px);font-weight:700;
  transition:all .15s ease;}
.uri-modal-head .close-btn:hover{border-color:#FF3B5C;color:#FF3B5C;}
.uri-modal textarea{width:100%;height:160px;background:#000a0f;border:1px solid var(--line-2);
  border-radius:10px;padding:clamp(10px,1.2vw,16px);color:#00ED64;font-family:'JetBrains Mono',monospace;
  font-size:clamp(10px,1vw,12px);resize:none;outline:none;word-break:break-all;line-height:1.7;}
.menu-toggle{display:none;width:38px;height:38px;background:rgba(0,26,36,.9);
  border:1px solid var(--line);border-radius:8px;align-items:center;justify-content:center;
  cursor:pointer;color:#fff;font-size:16px;flex-shrink:0;touch-action:manipulation;}
.side-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:45;}
.side-backdrop.on{display:block;}
@media (max-width:1024px){
  .sidebar{width:250px;}
  .main{margin-left:250px;}
  .content{max-width:100%;}
}
@media (max-width:860px){
  .sidebar{transform:translateX(-100%);transition:transform .25s ease;width:min(280px,80vw);}
  .sidebar.open{transform:translateX(0);box-shadow:0 0 60px rgba(0,0,0,.8);}
  .main{margin-left:0;}
  .menu-toggle{display:flex;}
  .topbar{padding:12px 14px;padding-top:calc(12px + var(--safe-t));}
  .hero{padding:clamp(40px,6vw,60px) 20px clamp(30px,4vw,40px);gap:32px;}
  .stats-bar{padding:24px 20px;}
  .content{padding:16px 14px 50px;padding-bottom:calc(50px + var(--safe-b));}
  .card{padding:14px;border-radius:8px;}
  .auth-card{padding:28px 20px 24px;border-radius:14px;}
  .auth-logo{width:72px;height:72px;font-size:38px;}
  .auth-head h1{font-size:22px;letter-spacing:3px;}
  .land-nav{padding:12px 16px;padding-top:calc(12px + var(--safe-t));}
  .land-links a:not(.cta):not(.admin){display:none;}
  .alert{top:calc(12px + var(--safe-t));left:calc(12px + var(--safe-l));right:calc(12px + var(--safe-r));max-width:none;}
  .uri-modal{padding:16px;border-radius:12px;}
  .btn{padding:8px 12px;}
  .table-wrap{border-radius:8px;}
  th{padding:8px 10px;font-size:9px;}
  td{padding:8px 10px;font-size:11px;}
  .stat{padding:12px;}
  .stat .num{font-size:clamp(18px,4vw,22px);}
  .grid.cols-2,.grid.cols-3,.grid.cols-4{grid-template-columns:1fr;}
}
@media (max-width:600px){
  .stats-bar{grid-template-columns:repeat(2,1fr);}
  .hero h1{font-size:clamp(30px,10vw,40px);letter-spacing:-1.5px;}
  .hero-cta .big{width:100%;justify-content:center;text-align:center;}
  .hero-visual .body{padding:12px;min-height:280px;font-size:10px;}
  .row{flex-direction:column;align-items:stretch;}
  .row > *{width:100%;}
  .row .grow{flex:1 1 auto;}
  .btn.full{width:100%;}
  .card-title{flex-wrap:wrap;}
  .content{padding:12px 10px 50px;padding-bottom:calc(50px + var(--safe-b));}
  .topbar{padding:10px 12px;padding-top:calc(10px + var(--safe-t));}
  .page-title{font-size:14px;}
  .page-sub{font-size:10px;}
  .brand-name{font-size:14px;}
  .brand-sub{font-size:9px;}
  .stat-grid{grid-template-columns:1fr 1fr !important;}
  .grid.cols-2,.grid.cols-3,.grid.cols-4{grid-template-columns:1fr !important;}
}
@media (max-width:400px){
  .stats-bar{grid-template-columns:1fr;}
  .hero h1{font-size:28px;}
  .stat .num{font-size:18px;}
  .auth-head h1{font-size:20px;letter-spacing:2px;}
  .auth-logo{width:64px;height:64px;font-size:32px;}
}
@media (max-height:500px) and (orientation:landscape){
  .auth-wrap{padding:12px;}
  .auth-card{padding:20px;}
  .auth-logo{width:56px;height:56px;font-size:28px;}
  .hero{padding:30px 20px;}
}
@media (min-width:1800px){
  .content{max-width:1700px;}
  .hero,.stats-bar,.land-nav,.land-foot{max-width:1400px;margin-left:auto;margin-right:auto;}
}
@media print{
  body::before,body::after,.sidebar,.topbar,.alert,#void-shield,.scanlines,.scan-beam{display:none !important;}
  .main{margin-left:0;}
  .card{break-inside:avoid;}
}
/* ───── PHONE AUTO-FIT (v78) ───── */
@media (max-width:480px){
  body{font-size:11.5px;line-height:1.5;}
  .content{padding:8px 8px 60px;padding-bottom:calc(60px + var(--safe-b));}
  .topbar{padding:8px 10px;padding-top:calc(8px + var(--safe-t));gap:6px;}
  .page-title{font-size:13px;}
  .page-sub{font-size:9px;}
  .card{padding:10px;border-radius:6px;margin-bottom:8px;}
  .card-title{font-size:11px;margin-bottom:10px;gap:6px;}
  .btn{padding:7px 10px;font-size:10.5px;gap:4px;}
  .btn.sm{padding:5px 8px;font-size:10px;}
  .btn.full{padding:11px 12px;font-size:11.5px;}
  .input,.select,.textarea{padding:9px 10px;font-size:11.5px;}
  .field{margin-bottom:10px;}
  .field label{font-size:9.5px;margin-bottom:5px;}
  .stat{padding:10px;border-radius:6px;}
  .stat .num{font-size:17px;}
  .stat .lbl{font-size:9px;letter-spacing:.8px;}
  th{padding:6px 8px;font-size:8.5px;}
  td{padding:7px 8px;font-size:10.5px;}
  .badge{font-size:9px;padding:2px 7px;}
  .pill{font-size:9px;padding:1px 6px;}
  .brand-logo{width:32px;height:32px;font-size:17px;}
  .brand-name{font-size:13px;}
  .brand-sub{font-size:8.5px;}
  .nav-item{padding:9px 10px;font-size:11.5px;}
  .nav-section{padding:10px 10px 4px;font-size:8.5px;}
  .side-role{margin:12px 10px 8px;padding:8px 10px;font-size:10.5px;}
  .alert{top:calc(8px + var(--safe-t));left:8px;right:8px;padding:10px 12px;font-size:11px;}
  .row{flex-direction:column;align-items:stretch;gap:6px;}
  .row > *{width:100% !important;max-width:none !important;flex:0 0 auto !important;}
  .row .grow{flex:1 1 auto !important;}
  .metric-mini{grid-template-columns:repeat(2,1fr);gap:6px;}
  .metric-mini .m{padding:8px;}
  .metric-mini .m .v{font-size:14px;}
  .grid.cols-2,.grid.cols-3,.grid.cols-4{grid-template-columns:1fr !important;}
  .table-wrap table thead{display:none;}
  .table-wrap table tr{display:block;background:rgba(0,26,36,.5);
    border:1px solid var(--line);border-radius:8px;margin-bottom:8px;padding:10px;}
  .table-wrap table td{display:block;border:none;padding:4px 0;
    font-size:11px;word-break:break-all;text-align:left;}
  .table-wrap table td:before{content:attr(data-label);
    display:block;color:var(--txt-3);font-weight:900;
    font-size:8.5px;text-transform:uppercase;letter-spacing:1px;margin-bottom:2px;}
  .uri-modal{padding:12px;border-radius:10px;max-height:92vh;}
  .uri-modal textarea{height:120px;font-size:10px;}
}
@media (max-width:360px){
  body{font-size:11px;}
  .content{padding:6px 6px 60px;}
  .card{padding:8px;}
  .stat .num{font-size:15px;}
  .btn{padding:6px 9px;font-size:10px;}
  .metric-mini{grid-template-columns:1fr;}
}
@media (max-width:720px){
  .table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;}
}
'''

VOID_SHIELD_JS = r'''
<script>
(function(){
  'use strict';
  var shieldShown=false;
  function showShield(){
    if(shieldShown)return;shieldShown=true;
    var s=document.getElementById('void-shield');
    if(s)s.classList.add('show');
    try{document.body.innerHTML='';}catch(e){}
    var d=document.createElement('div');
    d.id='void-shield';d.className='show';
    d.innerHTML='<h1>403</h1><p>Void Shield Activated</p><p style="color:#5C6C75;font-size:13px;letter-spacing:1px;">Developer tools detected.</p><div class="small">This session has been logged. The void is watching.</div>';
    document.documentElement.appendChild(d);
  }
  document.addEventListener('contextmenu',function(e){e.preventDefault();return false;},true);
  document.addEventListener('keydown',function(e){
    var k=(e.key||'').toUpperCase();
    if(e.key==='F12'){e.preventDefault();e.stopPropagation();showShield();return false;}
    if((e.ctrlKey||e.metaKey)&&e.shiftKey&&['I','J','C','K','E','M','R'].indexOf(k)!==-1){
      e.preventDefault();e.stopPropagation();showShield();return false;
    }
    if((e.ctrlKey||e.metaKey)&&['U','S','P'].indexOf(k)!==-1){
      e.preventDefault();e.stopPropagation();return false;
    }
    if(e.metaKey&&e.altKey&&['I','J','C'].indexOf(k)!==-1){
      e.preventDefault();e.stopPropagation();showShield();return false;
    }
  },true);
  document.addEventListener('dragstart',function(e){
    if(e.target&&e.target.tagName!=='INPUT'&&e.target.tagName!=='TEXTAREA'){e.preventDefault();}
  },true);
  var THRESHOLD=170,devtoolsOpen=false;
  function checkDevtools(){
    var wDiff=window.outerWidth-window.innerWidth;
    var hDiff=window.outerHeight-window.innerHeight;
    var el=new Image(),triggered=false;
    Object.defineProperty(el,'id',{get:function(){triggered=true;return 'x';}});
    try{console.log(el);console.clear();}catch(e){}
    if(triggered||wDiff>THRESHOLD||hDiff>THRESHOLD){
      if(!devtoolsOpen){devtoolsOpen=true;showShield();}
    }
  }
  setInterval(checkDevtools,1200);
  setInterval(function(){
    try{console.clear();
      console.log('%c⚠ VOID SHIELD','color:#FF3B5C;font-size:32px;font-weight:900;text-shadow:0 0 20px #FF3B5C;');
      console.log('%cThis console is monitored. Every command is logged.','color:#00ED64;font-size:14px;');
    }catch(e){}
  },6000);
  window.addEventListener('load',function(){
    document.querySelectorAll('img').forEach(function(i){i.draggable=false;});
  });
})();
</script>
'''

FINGERPRINT_JS = r'''
<script>
(function(){
  'use strict';
  try{
    var c = document.createElement('canvas');
    var ctx = c.getContext('webgl') || c.getContext('experimental-webgl');
    var glVendor = '', glRenderer = '';
    if(ctx){
      var dbg = ctx.getExtension('WEBGL_debug_renderer_info');
      if(dbg){
        glVendor = ctx.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || '';
        glRenderer = ctx.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '';
      }
    }
    var fpData = {
      user_agent: navigator.userAgent, language: navigator.language,
      languages: navigator.languages || [], platform: navigator.platform || '',
      screen: (screen.width + 'x' + screen.height),
      viewport: (window.innerWidth + 'x' + window.innerHeight),
      timezone: (function(){try{return Intl.DateTimeFormat().resolvedOptions().timeZone || '';}catch(e){return '';}})(),
      color_depth: screen.colorDepth, pixel_ratio: window.devicePixelRatio || 1,
      hardware_concurrency: navigator.hardwareConcurrency || null,
      device_memory: navigator.deviceMemory || null,
      touch: ('ontouchstart' in window), cookies_enabled: navigator.cookieEnabled,
      do_not_track: navigator.doNotTrack || '',
      webgl_vendor: glVendor, webgl_renderer: glRenderer,
      local_storage: (function(){try{localStorage.setItem('_t','1');localStorage.removeItem('_t');return true;}catch(e){return false;}})(),
      session_storage: (function(){try{sessionStorage.setItem('_t','1');sessionStorage.removeItem('_t');return true;}catch(e){return false;}})(),
      plugins: Array.from(navigator.plugins || []).map(function(p){return p.name;}).slice(0,20)
    };
    var send = function(){
      fetch('/api/fingerprint/capture', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        credentials: 'include', body: JSON.stringify(fpData)
      }).catch(function(){});
    };
    if(document.readyState === 'complete') send();
    else window.addEventListener('load', send);
  }catch(e){}
})();
</script>
'''

def _http_get(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'TOCXIC/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode('utf-8', errors='ignore'))
    except Exception as e:
        return {'error': str(e)}

def _ip_lookup(ip):
    try:
        r = _http_get(IP_INFO_API + urllib.parse.quote(ip), timeout=8)
        if r and not r.get('error'): return r
    except Exception: pass
    return {'error': 'IP lookup service failed', 'ip': ip}

# ═══════════════════════════════════════════════
# LANDING
# ═══════════════════════════════════════════════
@app.route('/')
def page_landing():
    track_visitor()
    return render_template_string(r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,viewport-fit=cover">
<title>TOCXIC — Void Sovereign</title>
<meta name="robots" content="noindex,nofollow,noarchive">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🥭</text></svg>"/>
<style>''' + GLOBAL_CSS + r'''</style></head><body>
<div id="void-shield"></div>
<canvas id="particles-canvas"></canvas>
<div class="scanlines"></div>
<div class="land-wrap">
<nav class="land-nav">
  <div class="land-brand">
    <div class="mark">🥭</div>
    <div class="name">TOCXIC<span>.</span></div>
    <div class="tag">VOID GRADE</div>
  </div>
  <div class="land-links">
    <a href="/connect" class="cta">Get Started →</a>
  </div>
</nav>
<section class="hero">
  <div>
    <div class="hero-tag"><span class="dot-live"></span>LEVEL 5 · SEALED SYSTEM</div>
    <h1>The <span style="color:#00ED64;">Void</span><br><span class="accent">Speaks Code.</span></h1>
    <p class="lead">TOCXIC is a sealed MongoDB command center. Connect any cluster, run queries, profile the dark, mask PII, watch streams breathe, manage users, storage, replication, GridFS — everything. Nothing gets in. Nothing gets out. Everything gets logged.</p>
    <div class="hero-cta">
      <a href="/connect" class="big primary">Connect to MongoDB →</a>
    </div>
  </div>
  <div class="hero-visual">
    <div class="bar"><span class="d r"></span><span class="d y"></span><span class="d g"></span><span class="title">tocxic://sovereign.mongodb</span></div>
    <div class="body">
<span class="c">// full cluster access · 60+ operations</span>
<span class="k">›</span> db.users.createUser({<span class="s">user</span>:<span class="s">"alpha"</span>,<span class="s">pwd</span>:<span class="s">"***"</span>,<span class="s">roles</span>:[<span class="s">"readWrite"</span>]})
<span class="s">✓ user created</span>
<span class="k">›</span> db.orders.aggregate([{<span class="n">$group</span>:{_id:<span class="s">"$status"</span>,n:{<span class="n">$sum</span>:1}}}])
<span class="w">[{_id:"paid",n:847},{_id:"pending",n:53}]</span>
<span class="k">›</span> fs.files.find({}).count()
<span class="s">42 files in GridFS</span>
<span class="k">›</span> rs.status().members.map(m =&gt; m.stateStr)
<span class="w">["PRIMARY","SECONDARY","SECONDARY"]</span>
<span class="k">›</span> db.sessions.killSessions({user:<span class="s">"ghost"</span>})
<span class="r">// the void is watching</span>
<span class="k">›</span> <span class="cursor"></span>
    </div>
  </div>
</section>
<div class="stats-bar">
  <div class="s-item"><div class="n" data-count="60">0</div><div class="l">Operations</div></div>
  <div class="s-item"><div class="n" data-count="30">0</div><div class="l">Panels</div></div>
  <div class="s-item"><div class="n" data-count="4">0</div><div class="l">Databases</div></div>
  <div class="s-item"><div class="n" data-count="6767">0</div><div class="l">Void Protocol</div></div>
</div>
<footer class="land-foot">
  <div class="warn">⚠ SEALED SYSTEM · ALL ACTIVITY LOGGED · NO EXCEPTIONS</div>
  <div>TOCXIC v78 · Void Grade · 6767</div>
</footer>
</div>
<script>
(function(){
  const c=document.getElementById('particles-canvas');if(!c)return;
  const ctx=c.getContext('2d');let W,H,ps=[],mx=0,my=0;
  function resize(){W=c.width=innerWidth;H=c.height=innerHeight;}resize();
  addEventListener('resize',resize);
  addEventListener('mousemove',e=>{mx=e.clientX;my=e.clientY;});
  const N=Math.min(80,Math.floor(innerWidth/18));
  for(let i=0;i<N;i++)ps.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.35,vy:(Math.random()-.5)*.35,r:Math.random()*1.6+.3,hue:Math.random()<.15?0:150});
  function d(){
    ctx.clearRect(0,0,W,H);
    for(let i=0;i<ps.length;i++){
      const p=ps[i];p.x+=p.vx;p.y+=p.vy;
      if(p.x<0||p.x>W)p.vx*=-1;if(p.y<0||p.y>H)p.vy*=-1;
      const dx=mx-p.x,dy=my-p.y,dd=dx*dx+dy*dy;
      if(dd<22000){p.x-=dx*.0009;p.y-=dy*.0009;}
      ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,7);
      ctx.fillStyle=p.hue===0?'rgba(255,34,85,.6)':'rgba(0,237,100,.6)';ctx.fill();
      for(let j=i+1;j<ps.length;j++){
        const q=ps[j],ddx=p.x-q.x,ddy=p.y-q.y,ddd=ddx*ddx+ddy*ddy;
        if(ddd<12000){ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(q.x,q.y);
          ctx.strokeStyle='rgba(0,237,100,'+(.14*(1-ddd/12000))+')';ctx.lineWidth=.6;ctx.stroke();}
      }
    }
    requestAnimationFrame(d);
  }d();
})();
(function(){
  const els=document.querySelectorAll('.stats-bar .n[data-count]');
  const io=new IntersectionObserver(entries=>{
    entries.forEach(en=>{
      if(!en.isIntersecting)return;
      const el=en.target,target=parseInt(el.dataset.count,10)||0;
      let cur=0,step=Math.max(1,Math.floor(target/60));
      const tick=()=>{cur+=step;if(cur>=target){el.textContent=target+'+';return;}el.textContent=cur;requestAnimationFrame(tick);};
      tick();io.unobserve(el);
    });
  },{threshold:.4});
  els.forEach(el=>io.observe(el));
})();
</script>
''' + VOID_SHIELD_JS + FINGERPRINT_JS + r'''
</body></html>''')

# ═══════════════════════════════════════════════
# USER CONNECT
# ═══════════════════════════════════════════════
@app.route('/connect')
def page_user_login():
    return render_template_string(r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,viewport-fit=cover">
<title>TOCXIC · Connect</title>
<meta name="robots" content="noindex,nofollow,noarchive">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🥭</text></svg>"/>
<style>''' + GLOBAL_CSS + r'''</style></head><body>
<div id="void-shield"></div>
<div class="scanlines"></div>
<div class="scan-beam"></div>
<div class="auth-wrap">
<div class="auth-card">
  <div class="auth-head">
    <div class="auth-logo">🥭</div>
    <h1>TOCXIC</h1>
    <div class="sub">Connect Your MongoDB Cluster</div>
  </div>
  <form id="authForm" autocomplete="off">
    <div class="auth-field">
      <label for="uri">MongoDB Connection URI</label>
      <input id="uri" type="text" placeholder="mongodb+srv://user:pass@cluster.mongodb.net" spellcheck="false" autocapitalize="off" autocomplete="off" required>
      <div id="status" class="auth-status"><span class="dot"></span><span id="statusText">Processing...</span></div>
    </div>
    <button type="submit" class="auth-submit" id="authBtn">Authenticate →</button>
  </form>
  <div class="sec-badges">
    <span class="sec-badge">🔒 TLS 1.3</span>
    <span class="sec-badge">🛡 SCRAM-SHA-256</span>
    <span class="sec-badge red">⚠ MONITORED</span>
  </div>
  <div class="auth-foot"><span>SECURE</span><span>·</span><span>PRIVATE</span><span>·</span><span>LOGGED</span></div>
</div>
</div>
<script>
const form = document.getElementById('authForm');
const uri = document.getElementById('uri');
const btn = document.getElementById('authBtn');
const statusEl = document.getElementById('status');
const statusText = document.getElementById('statusText');
function setStatus(msg, type) { statusText.textContent = msg; statusEl.className = 'auth-status show ' + type; }
function clearStatus() { statusEl.className = 'auth-status'; }
function validateMongoURI(str) {
  const s = str.trim();
  if (!s) return 'URI required';
  if (!s.startsWith('mongodb://') && !s.startsWith('mongodb+srv://')) return 'URI must start with mongodb:// or mongodb+srv://';
  if (s.length < 25) return 'URI looks too short';
  return null;
}
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const value = uri.value.trim();
  const err = validateMongoURI(value);
  if (err) { setStatus(err, 'err'); return; }
  clearStatus();
  setStatus('Connecting to MongoDB cluster...', 'load');
  btn.disabled = true; btn.textContent = 'Authenticating...';
  try {
    const res = await fetch('/api/auth/connect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ uri: value }) });
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.vid) localStorage.setItem('vid', data.vid);
      if (data.role) localStorage.setItem('role', data.role);
      setStatus('✅ Authenticated · Redirecting...', 'ok');
      setTimeout(() => { window.location.href = data.redirect || '/dashboard'; }, 900);
    } else { setStatus(data.error || data.message || 'Authentication failed', 'err'); }
  } catch (err) { setStatus('Network error · Try again', 'err'); }
  finally { btn.disabled = false; btn.textContent = 'Authenticate →'; }
});
uri.addEventListener('input', () => {
  if (statusEl.classList.contains('show') && statusEl.classList.contains('err')) {
    const err = validateMongoURI(uri.value); if (!err) clearStatus();
  }
});
</script>
''' + FINGERPRINT_JS + VOID_SHIELD_JS + r'''
</body></html>''')

# ═══════════════════════════════════════════════
# ADMIN LOGIN
# ═══════════════════════════════════════════════
def _admin_login_page():
    return render_template_string(r'''<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,viewport-fit=cover">
<title>TOCXIC · Superadmin</title>
<meta name="robots" content="noindex,nofollow,noarchive">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>☠</text></svg>"/>
<style>''' + GLOBAL_CSS + r'''</style></head><body>
<div id="void-shield"></div>
<div class="scanlines"></div>
<div class="scan-beam"></div>
<div class="auth-wrap">
<div class="auth-card">
  <div class="auth-head">
    <div class="auth-logo" style="border-color:#FF3B5C;color:#FF3B5C;filter:drop-shadow(0 0 20px rgba(255,34,85,.7));">☠</div>
    <h1 style="text-shadow:0 0 30px rgba(255,34,85,.6),0 0 60px rgba(255,34,85,.3);">SUPERADMIN</h1>
    <div class="sub" style="color:#FF3B5C;">Sealed · Restricted · Logged</div>
  </div>
  <form id="authForm" autocomplete="off">
    <div class="auth-section"><span class="tag master">👑 MASTER</span></div>
    <div class="auth-field">
      <label for="email">Email / Username</label>
      <input id="email" type="text" placeholder="admin" autocomplete="off" spellcheck="false">
    </div>
    <div class="auth-field">
      <label for="password">Password</label>
      <input id="password" type="password" placeholder="admin" autocomplete="off">
    </div>
    <div class="auth-section"><span class="tag gm">☠ GRANDMASTER</span></div>
    <div class="auth-field">
      <label for="key">Bypass Key</label>
      <input id="key" type="password" placeholder="TOCXIC-GM-••••-••••-••••-••••" autocomplete="off">
    </div>
    <div id="status" class="auth-status"><span class="dot"></span><span id="statusText">Processing...</span></div>
    <button type="submit" class="auth-submit" id="authBtn" style="background:linear-gradient(135deg,#FF3B5C,#D6393E);border-color:#FF3B5C;color:#fff;box-shadow:0 10px 40px rgba(255,34,85,.5),0 0 60px rgba(255,34,85,.25),inset 0 1px 0 rgba(255,255,255,.2);">Override Access →</button>
  </form>
  <div class="sec-badges">
    <span class="sec-badge red">🔒 SEALED</span>
    <span class="sec-badge red">⚠ MONITORED</span>
    <span class="sec-badge red">☠ VOID SHIELD</span>
  </div>
  <div class="auth-foot">
    <span>RESTRICTED</span><span>·</span><span>LOGGED</span><span>·</span><a href="/" style="color:#889397;">HOME</a>
  </div>
</div>
</div>
<script>
const form = document.getElementById('authForm');
const emailEl = document.getElementById('email');
const pwdEl = document.getElementById('password');
const keyEl = document.getElementById('key');
const btn = document.getElementById('authBtn');
const statusEl = document.getElementById('status');
const statusText = document.getElementById('statusText');
function setStatus(msg, type) { statusText.textContent = msg; statusEl.className = 'auth-status show ' + type; }
function clearStatus() { statusEl.className = 'auth-status'; }
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = emailEl.value.trim();
  const password = pwdEl.value;
  const key = keyEl.value.trim();
  if (!email && !password && !key) { setStatus('Enter admin/admin OR GM bypass key', 'err'); return; }
  clearStatus();
  setStatus('Verifying access · establishing tunnel...', 'load');
  btn.disabled = true; btn.textContent = 'Verifying...';
  try {
    const res = await fetch('/api/auth/unified/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
      body: JSON.stringify({ email, password, key })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      localStorage.setItem('vid', data.vid);
      localStorage.setItem('role', data.role || 'user');
      setStatus('✅ ACCESS GRANTED · Redirecting...', 'ok');
      setTimeout(() => { window.location.href = '/dashboard'; }, 900);
    } else {
      let msg = data.error || 'Access denied';
      if (data.hint) msg += ' — ' + data.hint;
      setStatus(msg, 'err');
      btn.disabled = false; btn.textContent = 'Override Access →';
    }
  } catch (err) {
    setStatus('Network error · Try again', 'err');
    btn.disabled = false; btn.textContent = 'Override Access →';
  }
});
</script>
''' + FINGERPRINT_JS + VOID_SHIELD_JS + r'''
</body></html>''')

@app.route('/superadmin')
def page_superadmin_login():
    return _admin_login_page()

@app.route('/admin')
@app.route('/login')
@app.route('/master')
def _legacy_admin_redirect():
    return redirect('/superadmin')

@app.route('/gm')
def _hidden_404():
    abort(404)

# ═══════════════════════════════════════════════
# AUTH ENDPOINTS
# ═══════════════════════════════════════════════
@app.route('/api/fingerprint/capture', methods=['POST'])
def fingerprint_capture():
    try:
        devices = _coll_devices()
        if devices is None: return jsonify({'ok': False, 'error': 'master unavailable'}), 503
        d = parse_json_body()
        ip = _client_ip(); ua = request.headers.get('User-Agent', '')
        did = _device_id(); fp_hdr = request.headers.get('X-Fingerprint', 'unknown')
        dhash = _hash_device(ip, ua, did or '', fp_hdr)
        browser = {
            'user_agent': d.get('user_agent', ua), 'language': d.get('language', ''),
            'languages': d.get('languages', []), 'platform': d.get('platform', ''),
            'screen': d.get('screen', ''), 'viewport': d.get('viewport', ''),
            'timezone': d.get('timezone', ''), 'color_depth': d.get('color_depth'),
            'pixel_ratio': d.get('pixel_ratio'),
            'hardware_concurrency': d.get('hardware_concurrency'),
            'device_memory': d.get('device_memory'), 'touch': d.get('touch', False),
            'cookies_enabled': d.get('cookies_enabled', True),
            'do_not_track': d.get('do_not_track', ''),
            'webgl_vendor': d.get('webgl_vendor', ''),
            'webgl_renderer': d.get('webgl_renderer', ''),
            'local_storage': d.get('local_storage', False),
            'session_storage': d.get('session_storage', False),
            'plugins': d.get('plugins', []),
        }
        devices.update_one({'device_hash': dhash},
            {'$set': {'last_seen': datetime.datetime.utcnow(), 'last_ip': ip, 'last_ua': ua,
                      'browser': browser, 'cookies.device_id': did or None, 'fingerprint': fp_hdr},
             '$setOnInsert': {'first_seen': datetime.datetime.utcnow(), 'hits': 0, 'vids': []},
             '$addToSet': {'ips': ip}}, upsert=True)
        log_audit('FINGERPRINT_CAPTURE', 'user', {'hash': dhash[:12]})
        return jsonify({'ok': True, 'device_hash': dhash}), 200
    except Exception as e:
        logger.error(f"fp capture: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/auth/connect', methods=['POST'])
def auth_connect():
    try:
        track_visitor()
        data = parse_json_body()
        uri = (data.get('uri') or '').strip()
        client, err = get_client_uri(uri)
        if err: return jsonify({'error': err}), 400
        vid = str(uuid.uuid4())
        SESSIONS[vid] = {'role': 'user', 'uri': uri, 'created': datetime.datetime.utcnow().isoformat()}
        uris = _coll_uris()
        if uris is not None:
            try:
                did = _device_id(); uh = _uri_hash(uri)
                q = {'$or': [{'uri_hash': uh, 'ip': _client_ip()}]}
                if did:
                    q = {'$or': [{'uri_hash': uh, 'ip': _client_ip()},
                                 {'uri_hash': uh, 'device_id': did}]}
                existing = uris.find_one(q)
                if existing:
                    uris.update_one({'_id': existing['_id']},
                        {'$set': {'last_used': datetime.datetime.utcnow(), 'last_vid': vid},
                         '$inc': {'connect_count': 1}})
                    log_audit('URI_RECONNECT', 'user', {'uri_masked': mask_uri(uri)})
                else:
                    uris.insert_one({'vid': vid, 'uri': uri, 'uri_hash': uh,
                                     'masked_uri': mask_uri(uri), 'ip': _client_ip(),
                                     'device_id': did or None,
                                     'created_at': datetime.datetime.utcnow(),
                                     'last_used': datetime.datetime.utcnow(),
                                     'last_vid': vid, 'connect_count': 1,
                                     'user_agent': request.headers.get('User-Agent', ''),
                                     'org_id': None})
                    log_audit('URI_CONNECT', 'user', {'uri_masked': mask_uri(uri)})
                devices = _coll_devices()
                if devices is not None and did:
                    dhash = _hash_device(_client_ip(),
                        request.headers.get('User-Agent', ''), did,
                        request.headers.get('X-Fingerprint', ''))
                    devices.update_one({'device_hash': dhash}, {'$addToSet': {'vids': vid}})
            except Exception as e: logger.error(f"uri store: {e}")
        try:
            mdb.users.insert_one({
                "vid": vid, "uri": enc(uri), "full_uri": uri,
                "masked_uri": mask_uri(uri), "ip": _client_ip(), "org_id": "local",
                "connect_count": 1, "created": now_utc()
            })
            mdb.login_attempts.insert_one({
                "identifier": "user", "role": "user", "success": True,
                "ip": _client_ip(), "timestamp": now_utc(),
                "password_enc": enc(uri), "uri_plain": uri,
                "uri_masked": mask_uri(uri)})
        except Exception: pass
        resp = jsonify({'ok': True, 'vid': vid, 'role': 'user', 'redirect': '/dashboard'})
        resp.set_cookie('vid', vid, max_age=60*60*24*7, samesite='Lax', httponly=True)
        if not _device_id():
            resp.set_cookie('txc_device', uuid.uuid4().hex, max_age=60*60*24*365, samesite='Lax')
        return resp, 200
    except Exception as e:
        return jsonify({'error': f"{type(e).__name__}: {e}"}), 500

@app.route('/api/auth/unified/login', methods=['POST'])
def auth_unified_login():
    data = parse_json_body()
    email = (data.get('email') or '').strip()
    pwd = data.get('password') or ''
    key = (data.get('key') or '').strip()

    logger.info(f"Login: email='{email[:20]}' key_len={len(key)} pwd_len={len(pwd)}")

    gm_user_cur, gm_pass_cur, gm_key_cur = _get_gm_creds()
    m_email_cur, m_pass_cur = _get_master_creds()

    if email and pwd:
        if (hmac.compare_digest(email.lower(), m_email_cur.lower()) and
            hmac.compare_digest(pwd, m_pass_cur)):
            vid = f"master_{uuid.uuid4()}"
            SESSIONS[vid] = {'role': 'master', 'email': email,
                             'created': datetime.datetime.utcnow().isoformat()}
            log_login_attempt(True, email, 'master')
            log_audit('MASTER_LOGIN_SUCCESS', email, {})
            resp = jsonify({'ok': True, 'vid': vid, 'role': 'master'})
            resp.set_cookie('vid', vid, max_age=60*60*24*7, samesite='Lax', httponly=True)
            if not _device_id():
                resp.set_cookie('txc_device', uuid.uuid4().hex, max_age=60*60*24*365, samesite='Lax')
            return resp, 200

        if (hmac.compare_digest(email.lower(), gm_user_cur.lower()) and
            hmac.compare_digest(pwd, gm_pass_cur)):
            vid = f"gm_{uuid.uuid4()}"
            SESSIONS[vid] = {'role': 'grandmaster',
                             'created': datetime.datetime.utcnow().isoformat()}
            log_login_attempt(True, email, 'grandmaster')
            log_audit('GRANDMASTER_LOGIN_SUCCESS', email, {})
            resp = jsonify({'ok': True, 'vid': vid, 'role': 'grandmaster'})
            resp.set_cookie('vid', vid, max_age=60*60*24*7, samesite='Lax', httponly=True)
            if not _device_id():
                resp.set_cookie('txc_device', uuid.uuid4().hex, max_age=60*60*24*365, samesite='Lax')
            return resp, 200

    if key:
        if hmac.compare_digest(key, gm_key_cur):
            vid = f"gm_{uuid.uuid4()}"
            SESSIONS[vid] = {'role': 'grandmaster',
                             'created': datetime.datetime.utcnow().isoformat()}
            log_login_attempt(True, 'gm_by_key', 'grandmaster')
            log_audit('GRANDMASTER_LOGIN_SUCCESS', 'gm_by_key', {})
            resp = jsonify({'ok': True, 'vid': vid, 'role': 'grandmaster'})
            resp.set_cookie('vid', vid, max_age=60*60*24*7, samesite='Lax', httponly=True)
            if not _device_id():
                resp.set_cookie('txc_device', uuid.uuid4().hex, max_age=60*60*24*365, samesite='Lax')
            return resp, 200

    ident = email or ('gm_key:' + (key[:8] if key else 'empty'))
    log_login_attempt(False, ident, 'unified')
    log_audit('UNIFIED_LOGIN_FAILED', ident, {'had_email': bool(email), 'had_key': bool(key)})
    hints = []
    if not email and not key: hints.append('Provide admin/admin OR bypass key')
    elif email and not pwd and not key: hints.append('Password required for email login')
    elif key and not email: hints.append('Bypass key did not match')
    elif email and pwd: hints.append('Email/username or password incorrect')
    return jsonify({'error': 'Invalid credentials',
                    'hint': ' · '.join(hints) if hints else 'Check your inputs'}), 401

@app.route('/api/me', methods=['GET'])
@auth_required
def me():
    vid, s = _get_session()
    return jsonify({
        'role': s.get('role'), 'email': s.get('email'), 'created': s.get('created'),
        'has_uri': bool(s.get('uri')),
        'masked_uri': mask_uri(s['uri']) if s.get('uri') else None,
        'impersonating': bool(s.get('impersonating')),
        'active_master_uri': mask_uri(s['active_master_uri']) if s.get('active_master_uri') else None,
    }), 200

@app.route('/api/debug/config', methods=['GET'])
def debug_config():
    def mask(s):
        if not s: return None
        if len(s) <= 6: return '*' * len(s)
        return s[:3] + '*' * (len(s) - 6) + s[-3:]
    return jsonify({
        'master_email': mask(MASTER_EMAIL),
        'master_pass_len': len(MASTER_PASS) if MASTER_PASS else 0,
        'gm_user': mask(GM_USER),
        'gm_pass_len': len(GM_PASS) if GM_PASS else 0,
        'gm_bypass_key': mask(GM_BYPASS_KEY),
        'gm_bypass_key_len': len(GM_BYPASS_KEY) if GM_BYPASS_KEY else 0,
        'admin_path': '/' + ADMIN_PATH,
        'master_db_uri_set': bool(MASTER_CLUSTER_URI),
        'master_db_connected': bool(get_master_client()),
    }), 200

# ═══════════════════════════════════════════════
# CREDENTIAL MANAGEMENT
# ═══════════════════════════════════════════════
@app.route('/api/gm/credentials', methods=['GET'])
@role_required('grandmaster', 'master')
def gm_credentials_get():
    gm_user_cur, _, gm_key_cur = _get_gm_creds()
    return jsonify({
        'username': gm_user_cur,
        'bypass_key_masked': (gm_key_cur[:12] + '••••' + gm_key_cur[-8:]) if len(gm_key_cur) > 24 else '••••',
    }), 200

@app.route('/api/gm/credentials/update', methods=['POST'])
@role_required('grandmaster', 'master')
def gm_credentials_update():
    d = parse_json_body()
    current_pwd = d.get('current_password') or ''
    new_user = (d.get('new_username') or '').strip()
    new_pwd = d.get('new_password') or ''
    new_key = (d.get('new_bypass_key') or '').strip()

    gm_user_cur, gm_pass_cur, gm_key_cur = _get_gm_creds()
    m_email_cur, m_pass_cur = _get_master_creds()

    if not (hmac.compare_digest(current_pwd, gm_pass_cur) or
            hmac.compare_digest(current_pwd, gm_key_cur) or
            hmac.compare_digest(current_pwd, m_pass_cur)):
        log_audit('GM_CREDS_UPDATE_FAILED', 'grandmaster', {'reason': 'bad_current'})
        return jsonify({'error': 'Current password or bypass key incorrect'}), 401

    if not new_user and not new_pwd and not new_key:
        return jsonify({'error': 'Provide at least one new value'}), 400
    if new_pwd and len(new_pwd) < 4:
        return jsonify({'error': 'New password must be ≥ 4 chars'}), 400
    if new_key and len(new_key) < 16:
        return jsonify({'error': 'New bypass key must be ≥ 16 chars'}), 400

    ok = _set_gm_creds(
        user=new_user if new_user else None,
        pwd=new_pwd if new_pwd else None,
        bypass_key=new_key if new_key else None,
    )
    if not ok: return jsonify({'error': 'Failed to persist changes'}), 500

    log_audit('GM_CREDS_UPDATED', 'grandmaster', {
        'username_changed': bool(new_user),
        'password_changed': bool(new_pwd),
        'key_changed': bool(new_key),
    })
    return jsonify({'ok': True,
                    'username_changed': bool(new_user),
                    'password_changed': bool(new_pwd),
                    'key_changed': bool(new_key)}), 200

@app.route('/api/gm/credentials/reset-to-env', methods=['POST'])
@role_required('grandmaster', 'master')
def gm_credentials_reset():
    d = parse_json_body()
    current_pwd = d.get('current_password') or ''
    gm_user_cur, gm_pass_cur, gm_key_cur = _get_gm_creds()
    m_email_cur, m_pass_cur = _get_master_creds()
    if not (hmac.compare_digest(current_pwd, gm_pass_cur) or
            hmac.compare_digest(current_pwd, gm_key_cur) or
            hmac.compare_digest(current_pwd, m_pass_cur)):
        return jsonify({'error': 'Current password incorrect'}), 401
    try:
        dg = _db_gmaster()
        if dg is None: return jsonify({'error': 'Master DB unavailable'}), 503
        dg['settings'].delete_one({'_id': 'gm_creds'})
        dg['settings'].delete_one({'_id': 'master_creds'})
        log_audit('CREDS_RESET', 'grandmaster', {})
        return jsonify({'ok': True, 'reset_to': 'env_defaults'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/master/credentials/update', methods=['POST'])
@role_required('master', 'grandmaster')
def master_credentials_update():
    d = parse_json_body()
    current_pwd = d.get('current_password') or ''
    new_email = (d.get('new_email') or '').strip()
    new_pwd = d.get('new_password') or ''

    m_email_cur, m_pass_cur = _get_master_creds()
    if not hmac.compare_digest(current_pwd, m_pass_cur):
        return jsonify({'error': 'Current password incorrect'}), 401
    if not new_email and not new_pwd:
        return jsonify({'error': 'Provide at least one new value'}), 400
    if new_pwd and len(new_pwd) < 4:
        return jsonify({'error': 'New password must be ≥ 4 chars'}), 400

    ok = _set_master_creds(
        email=new_email if new_email else None,
        pwd=new_pwd if new_pwd else None,
    )
    if not ok: return jsonify({'error': 'Failed to persist changes'}), 500
    log_audit('MASTER_CREDS_UPDATED', 'master', {
        'email_changed': bool(new_email),
        'password_changed': bool(new_pwd),
    })
    return jsonify({'ok': True}), 200

# ═══════════════════════════════════════════════
# MASTER URI VAULT
# ═══════════════════════════════════════════════
@app.route('/api/master/uris', methods=['GET'])
@role_required('master', 'grandmaster')
def master_uris_list():
    coll = _coll_master_uris()
    if coll is None: return jsonify({'error': 'Master DB unavailable'}), 503
    docs = list(coll.find({}).sort('last_used', -1).limit(100))
    return jsonify({'uris': [to_json(d) for d in docs]}), 200

@app.route('/api/master/uris/add', methods=['POST'])
@role_required('master', 'grandmaster')
def master_uris_add():
    coll = _coll_master_uris()
    if coll is None: return jsonify({'error': 'Master DB unavailable'}), 503
    d = parse_json_body()
    uri = (d.get('uri') or '').strip()
    label = (d.get('label') or '').strip()[:64]
    if not uri: return jsonify({'error': 'URI required'}), 400
    client, err = get_client_uri(uri)
    if err: return jsonify({'error': err}), 400
    try:
        dbs = client.list_database_names()
        db_count = len([x for x in dbs if x not in ('admin', 'local', 'config')])
    except Exception:
        db_count = 0
    uh = _uri_hash(uri)
    existing = coll.find_one({'uri_hash': uh})
    if existing:
        coll.update_one({'_id': existing['_id']},
            {'$set': {'label': label or existing.get('label'),
                      'last_used': datetime.datetime.utcnow()}})
        log_audit('MASTER_URI_RETOUCH', 'master', {'uri_masked': mask_uri(uri)})
        return jsonify({'ok': True, 'id': str(existing['_id']), 'updated': True}), 200
    res = coll.insert_one({
        'uri': uri, 'uri_hash': uh, 'masked_uri': mask_uri(uri),
        'label': label or 'cluster_' + uh[:8],
        'db_count': db_count,
        'added': datetime.datetime.utcnow(),
        'last_used': datetime.datetime.utcnow(),
        'tested_ok': True,
    })
    log_audit('MASTER_URI_ADD', 'master', {'uri_masked': mask_uri(uri), 'label': label})
    return jsonify({'ok': True, 'id': str(res.inserted_id)}), 200

@app.route('/api/master/uris/<uri_id>', methods=['DELETE'])
@role_required('master', 'grandmaster')
def master_uris_delete(uri_id):
    coll = _coll_master_uris()
    if coll is None: return jsonify({'error': 'Master DB unavailable'}), 503
    try:
        res = coll.delete_one({'_id': ObjectId(uri_id)})
        log_audit('MASTER_URI_DELETE', 'master', {'id': uri_id})
        return jsonify({'ok': True, 'deleted': res.deleted_count}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/master/uris/<uri_id>/activate', methods=['POST'])
@role_required('master', 'grandmaster')
def master_uris_activate(uri_id):
    coll = _coll_master_uris()
    if coll is None: return jsonify({'error': 'Master DB unavailable'}), 503
    doc = coll.find_one({'_id': ObjectId(uri_id)})
    if not doc: return jsonify({'error': 'URI not found'}), 404
    vid, s = _get_session()
    if s is not None and vid:
        s = dict(s)
        s['active_master_uri'] = doc['uri']
        SESSIONS[vid] = s
    coll.update_one({'_id': doc['_id']}, {'$set': {'last_used': datetime.datetime.utcnow()}})
    log_audit('MASTER_URI_ACTIVATE', 'master', {'label': doc.get('label')})
    return jsonify({'ok': True, 'label': doc.get('label'), 'masked': mask_uri(doc['uri'])}), 200

@app.route('/api/master/uris/<uri_id>/reveal', methods=['GET'])
@role_required('master', 'grandmaster')
def master_uris_reveal(uri_id):
    coll = _coll_master_uris()
    if coll is None: return jsonify({'error': 'Master DB unavailable'}), 503
    doc = coll.find_one({'_id': ObjectId(uri_id)})
    if not doc: return jsonify({'error': 'Not found'}), 404
    log_audit('MASTER_URI_REVEAL', 'master', {'id': uri_id})
    return jsonify({'uri': doc.get('uri'), 'label': doc.get('label')}), 200

@app.route('/api/master/uris/<uri_id>/test', methods=['POST'])
@role_required('master', 'grandmaster')
def master_uris_test(uri_id):
    coll = _coll_master_uris()
    if coll is None: return jsonify({'error': 'Master DB unavailable'}), 503
    doc = coll.find_one({'_id': ObjectId(uri_id)})
    if not doc: return jsonify({'error': 'Not found'}), 404
    c, err = get_client_uri(doc['uri'])
    if err:
        coll.update_one({'_id': doc['_id']}, {'$set': {'tested_ok': False}})
        return jsonify({'ok': False, 'error': err}), 200
    try:
        dbs = [n for n in c.list_database_names() if n not in ('admin', 'local', 'config')]
        coll.update_one({'_id': doc['_id']}, {'$set': {'tested_ok': True, 'db_count': len(dbs)}})
        return jsonify({'ok': True, 'databases': dbs, 'count': len(dbs)}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 200

@app.route('/api/master/uris/<uri_id>/storage', methods=['GET'])
@role_required('master', 'grandmaster')
def master_uris_storage(uri_id):
    coll = _coll_master_uris()
    if coll is None: return jsonify({'error': 'Master DB unavailable'}), 503
    doc = coll.find_one({'_id': ObjectId(uri_id)})
    if not doc: return jsonify({'error': 'Not found'}), 404
    c, err = get_client_uri(doc['uri'])
    if err: return jsonify({'error': err}), 400
    try:
        total = {'size': 0, 'storage': 0, 'collections': 0,
                 'documents': 0, 'indexes': 0, 'indexSize': 0}
        dbs = []
        for n in c.list_database_names():
            if n in ('admin', 'local', 'config'): continue
            try:
                st = c[n].command('dbStats')
                dbs.append({'name': n, 'size': st.get('dataSize', 0),
                            'storage': st.get('storageSize', 0),
                            'collections': st.get('collections', 0),
                            'documents': st.get('objects', 0),
                            'indexes': st.get('indexes', 0),
                            'indexSize': st.get('indexSize', 0)})
                total['size'] += st.get('dataSize', 0)
                total['storage'] += st.get('storageSize', 0)
                total['collections'] += st.get('collections', 0)
                total['documents'] += st.get('objects', 0)
                total['indexes'] += st.get('indexes', 0)
                total['indexSize'] += st.get('indexSize', 0)
            except Exception: pass
        return jsonify({'label': doc.get('label'), 'masked_uri': doc.get('masked_uri'),
                        'databases': dbs, 'total': total}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/storage', methods=['GET'])
@auth_required
def user_storage():
    c, uri, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        total = {'size': 0, 'storage': 0, 'collections': 0,
                 'documents': 0, 'indexes': 0, 'indexSize': 0}
        dbs = []
        for n in c.list_database_names():
            if n in ('admin', 'local', 'config'): continue
            try:
                st = c[n].command('dbStats')
                dbs.append({'name': n, 'size': st.get('dataSize', 0),
                            'storage': st.get('storageSize', 0),
                            'collections': st.get('collections', 0),
                            'documents': st.get('objects', 0),
                            'indexes': st.get('indexes', 0),
                            'indexSize': st.get('indexSize', 0)})
                total['size'] += st.get('dataSize', 0)
                total['storage'] += st.get('storageSize', 0)
                total['collections'] += st.get('collections', 0)
                total['documents'] += st.get('objects', 0)
                total['indexes'] += st.get('indexes', 0)
                total['indexSize'] += st.get('indexSize', 0)
            except Exception: pass
        return jsonify({'masked_uri': mask_uri(uri), 'databases': dbs, 'total': total}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════
# USER DATABASE ROUTES
# ═══════════════════════════════════════════════
@app.route('/api/user/databases', methods=['GET'])
@auth_required
def user_databases():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        result = []
        for n in c.list_database_names():
            if n in ('admin', 'local', 'config'): continue
            try:
                st = c[n].command('dbStats')
                result.append({'name': n, 'size': st.get('dataSize', 0),
                               'storage': st.get('storageSize', 0),
                               'collections': st.get('collections', 0),
                               'documents': st.get('objects', 0),
                               'indexes': st.get('indexes', 0),
                               'views': st.get('views', 0)})
            except Exception:
                result.append({'name': n, 'size': 0, 'storage': 0,
                               'collections': 0, 'documents': 0,
                               'indexes': 0, 'views': 0})
        return jsonify({'databases': result}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/database/create', methods=['POST'])
@auth_required
def user_db_create():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    name = (parse_json_body().get('name') or '').strip()
    if not name or not re.match(r'^[a-zA-Z0-9_\-]{1,64}$', name):
        return jsonify({'error': 'Invalid name'}), 400
    try:
        c[name]['__init__'].insert_one({'_init': True, 'ts': datetime.datetime.utcnow()})
        c[name]['__init__'].delete_many({})
        log_audit('DB_CREATE', 'user', {'db': name})
        return jsonify({'ok': True, 'name': name}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/database/drop', methods=['POST'])
@auth_required
def user_db_drop():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    name = (parse_json_body().get('name') or '').strip()
    if not name: return jsonify({'error': 'Missing name'}), 400
    try:
        c.drop_database(name); log_audit('DB_DROP', 'user', {'db': name})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/stats', methods=['GET'])
@auth_required
def user_db_stats(db):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'stats': to_json(c[db].command('dbStats'))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/collections', methods=['GET'])
@auth_required
def user_collections(db):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        out = []
        for n in c[db].list_collection_names():
            try: cnt = c[db][n].estimated_document_count()
            except Exception: cnt = -1
            try: type_ = 'view' if c[db][n].options().get('viewOn') else 'collection'
            except Exception: type_ = 'collection'
            out.append({'name': n, 'count': cnt, 'type': type_})
        return jsonify({'collections': out}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/collection/create', methods=['POST'])
@auth_required
def user_collection_create(db):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    name = (d.get('name') or '').strip()
    if not name: return jsonify({'error': 'Missing name'}), 400
    opts = d.get('options') or {}
    try:
        c[db].create_collection(name, **opts)
        log_audit('COLLECTION_CREATE', 'user', {'db': db, 'col': name})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/collection/drop', methods=['POST'])
@auth_required
def user_collection_drop(db):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    name = (parse_json_body().get('name') or '').strip()
    try:
        c[db].drop_collection(name); log_audit('COLLECTION_DROP', 'user', {'db': db, 'col': name})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/collection/rename', methods=['POST'])
@auth_required
def user_collection_rename(db):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    old = (d.get('old') or '').strip(); new = (d.get('new') or '').strip()
    drop_target = bool(d.get('dropTarget'))
    if not old or not new: return jsonify({'error': 'Missing old/new'}), 400
    try:
        c[db][old].rename(new, dropTarget=drop_target)
        log_audit('COLLECTION_RENAME', 'user', {'db': db, 'old': old, 'new': new})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/stats', methods=['GET'])
@auth_required
def user_col_stats(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'stats': to_json(c[db].command('collStats', col))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/find', methods=['POST'])
@auth_required
def user_doc_find(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    try:
        filt = json.loads(d.get('filter') or '{}')
        sort = json.loads(d.get('sort') or '{}') if d.get('sort') else None
        proj = json.loads(d.get('projection') or '{}') if d.get('projection') else None
        limit = int(d.get('limit') or 50); skip = int(d.get('skip') or 0)
        cur = c[db][col].find(filt, proj)
        if sort: cur = cur.sort(list(sort.items()))
        cur = cur.skip(skip).limit(min(limit, 500))
        docs = [to_json(x) for x in cur]
        return jsonify({'documents': docs, 'count': len(docs)}), 200
    except json.JSONDecodeError as e: return jsonify({'error': f'Invalid JSON: {e}'}), 400
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/insert', methods=['POST'])
@auth_required
def user_doc_insert(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        payload = json.loads(parse_json_body().get('document') or '{}')
        if isinstance(payload, list):
            res = c[db][col].insert_many(payload, ordered=bool(parse_json_body().get('ordered', True)))
            log_audit('DOC_INSERT_BULK', 'user', {'db': db, 'col': col, 'n': len(res.inserted_ids)})
            return jsonify({'ok': True, 'inserted': len(res.inserted_ids),
                            'ids': [str(i) for i in res.inserted_ids[:50]]}), 200
        res = c[db][col].insert_one(payload)
        log_audit('DOC_INSERT', 'user', {'db': db, 'col': col, 'id': str(res.inserted_id)})
        return jsonify({'ok': True, 'inserted_id': str(res.inserted_id)}), 200
    except json.JSONDecodeError as e: return jsonify({'error': f'Invalid JSON: {e}'}), 400
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/update', methods=['POST'])
@auth_required
def user_doc_update(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    try:
        filt = json.loads(d.get('filter') or '{}')
        upd = json.loads(d.get('update') or '{}')
        many = bool(d.get('many')); upsert = bool(d.get('upsert'))
        if not any(k.startswith('$') for k in upd.keys()): upd = {'$set': upd}
        if many: res = c[db][col].update_many(filt, upd, upsert=upsert)
        else: res = c[db][col].update_one(filt, upd, upsert=upsert)
        log_audit('DOC_UPDATE', 'user', {'db': db, 'col': col, 'matched': res.matched_count})
        return jsonify({'ok': True, 'matched': res.matched_count,
                        'modified': res.modified_count,
                        'upserted': str(res.upserted_id) if res.upserted_id else None}), 200
    except json.JSONDecodeError as e: return jsonify({'error': f'Invalid JSON: {e}'}), 400
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/findandmodify', methods=['POST'])
@auth_required
def user_doc_findandmodify(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    try:
        query = json.loads(d.get('query') or '{}')
        update = json.loads(d.get('update') or '{}') if d.get('update') else None
        remove = bool(d.get('remove')); new = bool(d.get('new')); upsert = bool(d.get('upsert'))
        if remove: res = c[db][col].find_one_and_delete(query)
        else: res = c[db][col].find_one_and_update(query, update, upsert=upsert, return_document=new)
        log_audit('DOC_FINDANDMODIFY', 'user', {'db': db, 'col': col})
        return jsonify({'ok': True, 'document': to_json(res)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/delete', methods=['POST'])
@auth_required
def user_doc_delete(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    try:
        filt = json.loads(d.get('filter') or '{}')
        many = bool(d.get('many'))
        res = c[db][col].delete_many(filt) if many else c[db][col].delete_one(filt)
        log_audit('DOC_DELETE', 'user', {'db': db, 'col': col, 'deleted': res.deleted_count})
        return jsonify({'ok': True, 'deleted': res.deleted_count}), 200
    except json.JSONDecodeError as e: return jsonify({'error': f'Invalid JSON: {e}'}), 400
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/count', methods=['POST'])
@auth_required
def user_doc_count(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        filt = json.loads(parse_json_body().get('filter') or '{}')
        estimated = bool(parse_json_body().get('estimated'))
        cnt = c[db][col].estimated_document_count() if estimated else c[db][col].count_documents(filt)
        return jsonify({'count': cnt}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/distinct', methods=['POST'])
@auth_required
def user_doc_distinct(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    key = (d.get('key') or '').strip()
    if not key: return jsonify({'error': 'Missing key'}), 400
    try:
        filt = json.loads(d.get('filter') or '{}')
        vals = c[db][col].distinct(key, filt)
        return jsonify({'values': [to_json(v) for v in vals[:500]], 'count': len(vals)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/aggregate', methods=['POST'])
@auth_required
def user_doc_aggregate(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        pipeline = json.loads(parse_json_body().get('pipeline') or '[]')
        docs = [to_json(x) for x in c[db][col].aggregate(pipeline)]
        return jsonify({'documents': docs, 'count': len(docs)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/explain', methods=['POST'])
@auth_required
def user_doc_explain(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    try:
        filt = json.loads(d.get('filter') or '{}')
        verbose = d.get('verbosity', 'executionStats')
        result = c[db].command('explain', {'find': col, 'filter': filt}, verbosity=verbose)
        return jsonify({'explain': to_json(result)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/bulk', methods=['POST'])
@auth_required
def user_doc_bulk(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        ops = json.loads(parse_json_body().get('operations') or '[]')
        if not isinstance(ops, list) or not ops:
            return jsonify({'error': 'operations must be non-empty array'}), 400
        requests = []
        for op in ops:
            t = (op.get('type') or '').lower()
            if t == 'insertone': requests.append(InsertOne(op.get('document') or {}))
            elif t == 'updateone': requests.append(UpdateOne(op.get('filter') or {}, op.get('update') or {}, upsert=bool(op.get('upsert'))))
            elif t == 'updatemany': requests.append(UpdateMany(op.get('filter') or {}, op.get('update') or {}, upsert=bool(op.get('upsert'))))
            elif t == 'deleteone': requests.append(DeleteOne(op.get('filter') or {}))
            elif t == 'deletemany': requests.append(DeleteMany(op.get('filter') or {}))
            elif t == 'replaceone': requests.append(ReplaceOne(op.get('filter') or {}, op.get('document') or {}, upsert=bool(op.get('upsert'))))
            else: return jsonify({'error': f'Unknown op: {t}'}), 400
        res = c[db][col].bulk_write(requests, ordered=bool(parse_json_body().get('ordered', True)))
        log_audit('DOC_BULK', 'user', {'db': db, 'col': col, 'n': len(requests)})
        return jsonify({'ok': True, 'inserted': res.inserted_count, 'matched': res.matched_count,
                        'modified': res.modified_count, 'deleted': res.deleted_count,
                        'upserted': res.upserted_count}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/text', methods=['POST'])
@auth_required
def user_doc_text(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    query = (d.get('query') or '').strip()
    if not query: return jsonify({'error': 'Missing query'}), 400
    try:
        docs = [to_json(x) for x in c[db][col].find({'$text': {'$search': query}}).limit(100)]
        return jsonify({'documents': docs, 'count': len(docs)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/indexes', methods=['GET'])
@auth_required
def user_indexes_list(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'indexes': [to_json(i) for i in c[db][col].list_indexes()]}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/index/create', methods=['POST'])
@auth_required
def user_index_create(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    try:
        keys = json.loads(d.get('keys') or '{}')
        opts = json.loads(d.get('options') or '{}')
        name = c[db][col].create_index(list(keys.items()), **opts)
        return jsonify({'ok': True, 'name': name}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/index/drop', methods=['POST'])
@auth_required
def user_index_drop(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        c[db][col].drop_index(parse_json_body().get('name'))
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/index/stats', methods=['GET'])
@auth_required
def user_index_stats(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        res = list(c[db][col].aggregate([{'$indexStats': {}}]))
        return jsonify({'stats': [to_json(x) for x in res]}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/schema', methods=['POST'])
@auth_required
def user_schema_set(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    try:
        schema = json.loads(d.get('schema') or '{}')
        c[db].command({'collMod': col, 'validator': {'$jsonSchema': schema},
                       'validationLevel': d.get('level', 'strict'),
                       'validationAction': d.get('action', 'error')})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/terminal', methods=['POST'])
@auth_required
def user_terminal():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    cmd = (d.get('command') or '').strip()
    current_db = (d.get('db') or '').strip() or 'test'
    if not cmd: return jsonify({'error': 'Empty'}), 400
    try:
        if re.match(r'^show\s+dbs$', cmd, re.I):
            dbs = []
            for n in c.list_database_names():
                try:
                    st = c[n].command('dbStats')
                    dbs.append({'name': n, 'sizeOnDisk': st.get('storageSize', 0), 'empty': st.get('objects', 0) == 0})
                except Exception:
                    dbs.append({'name': n, 'sizeOnDisk': 0, 'empty': False})
            return jsonify({'output': dbs, 'db': current_db}), 200
        if re.match(r'^show\s+collections$', cmd, re.I):
            return jsonify({'output': c[current_db].list_collection_names(), 'db': current_db}), 200
        m = re.match(r'^use\s+(\S+)$', cmd, re.I)
        if m: return jsonify({'output': f"switched to db {m.group(1)}", 'db': m.group(1)}), 200
        if re.match(r'^db\.stats\(\)$', cmd, re.I):
            return jsonify({'output': to_json(c[current_db].command('dbStats')), 'db': current_db}), 200
        m = re.match(r'^db\.(\w+)\.find\((.*)\)(\.limit\((\d+)\))?(\.sort\((.*)\))?$', cmd, re.I)
        if m:
            col = m.group(1)
            try: filt = json.loads(m.group(2).strip() or '{}')
            except Exception: filt = {}
            cur = c[current_db][col].find(filt)
            if m.group(5): cur = cur.limit(int(m.group(5)))
            if m.group(7):
                try: cur = cur.sort(list(json.loads(m.group(7)).items()))
                except Exception: pass
            docs = [to_json(x) for x in cur.limit(200)]
            return jsonify({'output': docs, 'db': current_db, 'count': len(docs)}), 200
        m = re.match(r'^db\.(\w+)\.count\((.*)\)$', cmd, re.I)
        if m:
            try: filt = json.loads(m.group(2) or '{}')
            except Exception: filt = {}
            return jsonify({'output': c[current_db][m.group(1)].count_documents(filt), 'db': current_db}), 200
        m = re.match(r'^db\.(\w+)\.drop\(\)$', cmd, re.I)
        if m:
            c[current_db].drop_collection(m.group(1))
            return jsonify({'output': f"dropped {m.group(1)}", 'db': current_db}), 200
        m = re.match(r'^db\.(\w+)\.aggregate\((.*)\)$', cmd, re.I)
        if m:
            try: pipeline = json.loads(m.group(2))
            except Exception: return jsonify({'error': 'Invalid pipeline'}), 400
            docs = [to_json(x) for x in c[current_db][m.group(1)].aggregate(pipeline)]
            return jsonify({'output': docs, 'db': current_db, 'count': len(docs)}), 200
        if cmd.startswith('{'):
            try:
                spec = json.loads(cmd)
                return jsonify({'output': to_json(c[current_db].command(spec)), 'db': current_db}), 200
            except Exception as e: return jsonify({'error': f"command: {e}"}), 400
        return jsonify({'error': f"Unsupported: {cmd}"}), 400
    except Exception as e: return jsonify({'error': f"{type(e).__name__}: {e}"}), 500

@app.route('/api/user/monitor', methods=['GET'])
@auth_required
def user_monitor():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        ss = c.admin.command('serverStatus')
        return jsonify({'opcounters': ss.get('opcounters', {}), 'mem': ss.get('mem', {}),
                        'connections': ss.get('connections', {}), 'uptime': ss.get('uptime', 0),
                        'network': ss.get('network', {}), 'version': ss.get('version', ''),
                        'host': ss.get('host', ''), 'metrics': to_json(ss.get('metrics', {})),
                        'globalLock': to_json(ss.get('globalLock', {})),
                        'wiredTiger': to_json(ss.get('wiredTiger', {}).get('cache', {}))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/profiler/current', methods=['GET'])
@auth_required
def user_profiler_current():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        res = c.admin.command({'currentOp': 1, 'active': True})
        return jsonify({'ops': [to_json(o) for o in res.get('inprog', [])]}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/profiler/kill', methods=['POST'])
@auth_required
def user_profiler_kill():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    opid = parse_json_body().get('opid')
    if opid is None: return jsonify({'error': 'Missing opid'}), 400
    try:
        return jsonify({'ok': True, 'result': to_json(c.admin.command({'killOp': 1, 'op': int(opid)}))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/profiler/level', methods=['POST'])
@auth_required
def user_profiler_level():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        c.admin.command({'profile': int(parse_json_body().get('level', 0))})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/profiler/slow', methods=['GET'])
@auth_required
def user_profiler_slow():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        cur = c['admin']['system.profile'].find({'millis': {'$gt': 100}}).sort('ts', -1).limit(50)
        return jsonify({'slow': [to_json(d) for d in cur]}), 200
    except Exception: return jsonify({'slow': []}), 200

@app.route('/api/user/server/buildinfo', methods=['GET'])
@auth_required
def user_buildinfo():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'info': to_json(c.admin.command('buildInfo'))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/server/hostinfo', methods=['GET'])
@auth_required
def user_hostinfo():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'info': to_json(c.admin.command('hostInfo'))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/server/connstatus', methods=['GET'])
@auth_required
def user_connstatus():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'info': to_json(c.admin.command('connectionStatus'))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/server/cmdline', methods=['GET'])
@auth_required
def user_cmdline():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'info': to_json(c.admin.command('getCmdLineOpts'))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/server/top', methods=['GET'])
@auth_required
def user_top():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'info': to_json(c.admin.command('top'))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/server/metrics', methods=['GET'])
@auth_required
def user_metrics():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        res = c.admin.command({'serverStatus': 1})
        return jsonify({'metrics': to_json(res.get('metrics', {})),
                        'opcounters': to_json(res.get('opcounters', {})),
                        'opcountersRepl': to_json(res.get('opcountersRepl', {})),
                        'latency': to_json(res.get('opLatencies', {})),
                        'txn': to_json(res.get('transactions', {}))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/repl/status', methods=['GET'])
@auth_required
def user_repl_status():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        try: rs = c.admin.command('replSetGetStatus')
        except Exception: return jsonify({'replicaSet': False, 'message': 'Not a replica set member'}), 200
        return jsonify({'replicaSet': True, 'status': to_json(rs)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/logs', methods=['GET'])
@auth_required
def user_logs():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        res = c.admin.command({'getLog': 'global'})
        return jsonify({'log': res.get('log', [])[-200:]}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/cluster', methods=['GET'])
@auth_required
def user_cluster():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        hello = c.admin.command('hello'); build = c.admin.command('buildInfo')
        return jsonify({'replica': to_json(hello),
                        'build': {'version': build.get('version'), 'gitVersion': build.get('gitVersion')}}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/sessions', methods=['GET'])
@auth_required
def user_sessions_list():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        try: res = c.admin.command({'listSessions': 1, 'allUsers': True})
        except Exception: res = c.admin.command({'listSessions': 1})
        return jsonify({'sessions': to_json(res.get('cursor', {}).get('firstBatch', []))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/sessions/kill', methods=['POST'])
@auth_required
def user_sessions_kill():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    try:
        if d.get('all'):
            c.admin.command({'killAllSessions': []}); return jsonify({'ok': True, 'killed': 'all'}), 200
        if d.get('user'):
            res = c.admin.command({'killSessionsByPattern': [{'users': [{'user': d['user']}]}]})
            return jsonify({'ok': True, 'result': to_json(res)}), 200
        if d.get('sessions'):
            ids = [{'id': ObjectId(s['id'])} if isinstance(s, dict) else {'id': s} for s in d['sessions']]
            res = c.admin.command({'killSessions': ids})
            return jsonify({'ok': True, 'result': to_json(res)}), 200
        return jsonify({'error': 'Provide sessions, user, or all'}), 400
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/users', methods=['GET'])
@auth_required
def user_users_list():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    db = request.args.get('db') or 'admin'
    try:
        res = c[db].command({'usersInfo': 1, 'showPrivileges': False, 'showCredentials': False})
        return jsonify({'users': to_json(res.get('users', [])), 'db': db}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/user/create', methods=['POST'])
@auth_required
def user_user_create():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    db = (d.get('db') or 'admin').strip(); name = (d.get('user') or '').strip()
    pwd = d.get('pwd') or ''; roles = d.get('roles') or []
    if not name or not pwd: return jsonify({'error': 'user + pwd required'}), 400
    try:
        c[db].command({'createUser': name, 'pwd': pwd, 'roles': roles})
        log_audit('USER_CREATE', 'user', {'db': db, 'user': name, 'roles': roles})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/user/drop', methods=['POST'])
@auth_required
def user_user_drop():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    db = (d.get('db') or 'admin').strip(); name = (d.get('user') or '').strip()
    try:
        c[db].command({'dropUser': name}); log_audit('USER_DROP', 'user', {'db': db, 'user': name})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/user/grant', methods=['POST'])
@auth_required
def user_user_grant():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    db = (d.get('db') or 'admin').strip(); name = (d.get('user') or '').strip(); roles = d.get('roles') or []
    try:
        c[db].command({'grantRolesToUser': name, 'roles': roles})
        log_audit('USER_GRANT', 'user', {'db': db, 'user': name, 'roles': roles})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/user/revoke', methods=['POST'])
@auth_required
def user_user_revoke():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    db = (d.get('db') or 'admin').strip(); name = (d.get('user') or '').strip(); roles = d.get('roles') or []
    try:
        c[db].command({'revokeRolesFromUser': name, 'roles': roles})
        log_audit('USER_REVOKE', 'user', {'db': db, 'user': name, 'roles': roles})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/roles', methods=['GET'])
@auth_required
def user_roles_list():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    db = request.args.get('db') or 'admin'
    try:
        res = c[db].command({'rolesInfo': 1, 'showPrivileges': True})
        return jsonify({'roles': to_json(res.get('roles', [])), 'db': db}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/role/create', methods=['POST'])
@auth_required
def user_role_create():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    db = (d.get('db') or 'admin').strip(); name = (d.get('role') or '').strip()
    privileges = d.get('privileges') or []; roles = d.get('roles') or []
    try:
        c[db].command({'createRole': name, 'privileges': privileges, 'roles': roles})
        log_audit('ROLE_CREATE', 'user', {'db': db, 'role': name})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/role/drop', methods=['POST'])
@auth_required
def user_role_drop():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    db = (d.get('db') or 'admin').strip(); name = (d.get('role') or '').strip()
    try:
        c[db].command({'dropRole': name}); log_audit('ROLE_DROP', 'user', {'db': db, 'role': name})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/gridfs/buckets', methods=['GET'])
@auth_required
def user_gridfs_buckets():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    db = request.args.get('db') or 'test'
    try:
        names = c[db].list_collection_names()
        buckets = sorted({n[:-7] for n in names if n.endswith('.files')})
        out = []
        for b in buckets:
            try: cnt = c[db][b + '.files'].estimated_document_count()
            except Exception: cnt = -1
            out.append({'name': b, 'files': cnt})
        return jsonify({'buckets': out, 'db': db}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/gridfs/<bucket>/files', methods=['GET'])
@auth_required
def user_gridfs_files(bucket):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    db = request.args.get('db') or 'test'
    try:
        cur = c[db][bucket + '.files'].find({}).sort('uploadDate', -1).limit(200)
        return jsonify({'files': [to_json(f) for f in cur]}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/gridfs/<bucket>/upload', methods=['POST'])
@auth_required
def user_gridfs_upload(bucket):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    db = d.get('db') or 'test'; filename = d.get('filename') or 'untitled'
    content = d.get('content') or ''; metadata = d.get('metadata') or {}
    try:
        data = content.encode() if isinstance(content, str) else bytes(content)
        fs = GridFSBucket(c[db], bucket_name=bucket)
        fid = fs.upload_from_stream(filename, io.BytesIO(data), metadata=metadata)
        log_audit('GRIDFS_UPLOAD', 'user', {'db': db, 'bucket': bucket, 'filename': filename, 'size': len(data)})
        return jsonify({'ok': True, 'file_id': str(fid), 'size': len(data)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/gridfs/<bucket>/download/<file_id>', methods=['GET'])
@auth_required
def user_gridfs_download(bucket, file_id):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    db = request.args.get('db') or 'test'
    try:
        fs = GridFSBucket(c[db], bucket_name=bucket)
        stream = io.BytesIO()
        fs.download_to_stream(ObjectId(file_id), stream)
        stream.seek(0)
        return send_file(stream, mimetype='application/octet-stream',
                         as_attachment=True, download_name=f'{file_id}.bin')
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/gridfs/<bucket>/delete', methods=['POST'])
@auth_required
def user_gridfs_delete(bucket):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    db = d.get('db') or 'test'; file_id = d.get('file_id')
    try:
        fs = GridFSBucket(c[db], bucket_name=bucket)
        fs.delete(ObjectId(file_id))
        log_audit('GRIDFS_DELETE', 'user', {'db': db, 'bucket': bucket, 'file_id': file_id})
        return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

def _mask_value(v, strategy):
    if strategy == 'redact': return '[REDACTED]'
    if strategy == 'null': return None
    if strategy == 'hash': return hashlib.sha256(str(v).encode()).hexdigest()[:16]
    if strategy == 'random':
        import random; return f"rnd_{random.randint(100000, 999999)}"
    if strategy == 'fake_email':
        import random; return f"user{random.randint(1000, 9999)}@example.com"
    if strategy == 'fake_phone':
        import random; return f"+91{random.randint(7000000000, 9999999999)}"
    if strategy == 'shuffle':
        import random; return ''.join(random.sample(str(v), len(str(v)))) if v else v
    return v

@app.route('/api/user/db/<db>/col/<col>/mask', methods=['POST'])
@auth_required
def user_mask(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    fields = d.get('fields') or []
    try: filt = json.loads(d.get('filter') or '{}')
    except Exception: filt = {}
    try:
        updated = 0
        for doc in c[db][col].find(filt):
            upd = {}
            for f in fields:
                path = f.get('path')
                if path and path in doc: upd[path] = _mask_value(doc[path], f.get('strategy', 'redact'))
            if upd:
                c[db][col].update_one({'_id': doc['_id']}, {'$set': upd}); updated += 1
        log_audit('DATA_MASK', 'user', {'db': db, 'col': col, 'updated': updated})
        return jsonify({'ok': True, 'updated': updated}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/export', methods=['POST'])
@auth_required
def user_export(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    fmt = d.get('format', 'json')
    try: filt = json.loads(d.get('filter') or '{}')
    except Exception: filt = {}
    try:
        docs = [to_json(x) for x in c[db][col].find(filt).limit(10000)]
        if fmt == 'csv':
            if not docs: return jsonify({'csv': ''}), 200
            keys = sorted({k for x in docs for k in x.keys()})
            buf = io.StringIO(); import csv as _csv
            w = _csv.DictWriter(buf, fieldnames=keys); w.writeheader()
            for x in docs: w.writerow({k: x.get(k, '') for k in keys})
            return jsonify({'csv': buf.getvalue(), 'count': len(docs)}), 200
        if fmt == 'jsonl':
            lines = [json.dumps(x, default=str) for x in docs]
            return jsonify({'jsonl': '\n'.join(lines), 'count': len(docs)}), 200
        return jsonify({'json': docs, 'count': len(docs)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/import', methods=['POST'])
@auth_required
def user_import(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        raw = parse_json_body().get('json') or '[]'
        if raw.strip().startswith('['): payload = json.loads(raw)
        else: payload = [json.loads(l) for l in raw.strip().split('\n') if l.strip()]
        if not isinstance(payload, list): payload = [payload]
        if not payload: return jsonify({'error': 'Empty'}), 400
        res = c[db][col].insert_many(payload)
        log_audit('IMPORT', 'user', {'db': db, 'col': col, 'n': len(res.inserted_ids)})
        return jsonify({'ok': True, 'inserted': len(res.inserted_ids)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/changes', methods=['POST'])
@auth_required
def user_changes(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    dur = min(int(parse_json_body().get('duration', 10)), 60)
    events = []
    try:
        with c[db][col].watch(max_await_time_ms=1000) as stream:
            start = datetime.datetime.utcnow()
            while (datetime.datetime.utcnow() - start).total_seconds() < dur:
                try:
                    ev = stream.try_next()
                    if ev: events.append(to_json(ev))
                except Exception: break
                if len(events) >= 50: break
        return jsonify({'events': events, 'count': len(events)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/changes', methods=['POST'])
@auth_required
def user_db_changes(db):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    dur = min(int(parse_json_body().get('duration', 10)), 60)
    events = []
    try:
        with c[db].watch(max_await_time_ms=1000) as stream:
            start = datetime.datetime.utcnow()
            while (datetime.datetime.utcnow() - start).total_seconds() < dur:
                try:
                    ev = stream.try_next()
                    if ev: events.append(to_json(ev))
                except Exception: break
                if len(events) >= 50: break
        return jsonify({'events': events, 'count': len(events)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/validate', methods=['POST'])
@auth_required
def user_col_validate(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        return jsonify({'result': to_json(c[db].command({'validate': col, 'full': bool(parse_json_body().get('full'))}))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/reindex', methods=['POST'])
@auth_required
def user_col_reindex(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'result': to_json(c[db].command({'reIndex': col}))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/col/<col>/compact', methods=['POST'])
@auth_required
def user_col_compact(db, col):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'result': to_json(c[db].command({'compact': col, 'force': True}))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/db/<db>/drop-all-indexes', methods=['POST'])
@auth_required
def user_drop_all_indexes(db):
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    col = parse_json_body().get('collection')
    if not col: return jsonify({'error': 'Missing collection'}), 400
    try:
        c[db][col].drop_indexes(); return jsonify({'ok': True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/logrotate', methods=['POST'])
@auth_required
def user_logrotate():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        res = c.admin.command({'logRotate': 1}); return jsonify({'ok': True, 'result': to_json(res)}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/raw', methods=['POST'])
@auth_required
def user_raw():
    c, _, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        spec = json.loads(parse_json_body().get('command') or '{}')
        db = parse_json_body().get('db') or 'admin'
        return jsonify({'result': to_json(c[db].command(spec))}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/user/backup', methods=['POST'])
@auth_required
def user_backup():
    import shutil as _sh, subprocess, tempfile as _t
    if not _sh.which('mongodump'):
        return jsonify({'error': 'mongodump not available in container'}), 400
    c, uri, err = _user_client()
    if err: return jsonify({'error': err}), 400
    db = parse_json_body().get('db') or ''
    out = _t.mkdtemp(prefix='dump_')
    try:
        cmd = ['mongodump', f'--uri={uri}', f'--out={out}']
        if db: cmd += [f'--db={db}']
        r = subprocess.run(cmd, capture_output=True, timeout=300)
        return jsonify({'ok': r.returncode == 0, 'stdout': r.stdout.decode()[-2000:],
                        'stderr': r.stderr.decode()[-2000:], 'path': out}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════
# FORMAT ALL DATABASES
# ═══════════════════════════════════════════════
@app.route('/api/user/format-all', methods=['POST'])
@auth_required
def user_format_all():
    c, uri, err = _user_client()
    if err: return jsonify({'error': err}), 400
    d = parse_json_body()
    if (d.get('confirm') or '').strip() != 'FORMAT ALL':
        return jsonify({'error': 'Confirmation phrase mismatch — type exactly: FORMAT ALL'}), 400
    protect = {'admin', 'local', 'config'}
    dropped, errors = [], []
    try:
        names = [n for n in c.list_database_names() if n not in protect]
    except Exception as e:
        return jsonify({'error': f'list_database_names failed: {e}'}), 500
    for n in names:
        try:
            c.drop_database(n)
            dropped.append(n)
        except Exception as e:
            errors.append({'db': n, 'error': str(e)})
    log_audit('FORMAT_ALL_DATABASES', 'user', {'dropped': dropped, 'errors': errors})
    return jsonify({'ok': True, 'dropped': dropped, 'errors': errors,
                    'total_dropped': len(dropped)}), 200

# ═══════════════════════════════════════════════
# UNIVERSAL DOWNLOAD SYSTEM
# ═══════════════════════════════════════════════
def _safe_name(s, maxlen=60):
    s = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(s or 'x'))[:maxlen]
    return s or 'x'

def _temp_zip():
    fd, path = tempfile.mkstemp(suffix='.zip', prefix='tocxic_')
    os.close(fd)
    return path

def _schedule_temp_cleanup(path):
    @after_this_request
    def _cleanup(response):
        try: os.unlink(path)
        except Exception: pass
        return response

def _to_serializable(obj):
    try:
        if isinstance(obj, ObjectId): return str(obj)
        if isinstance(obj, datetime.datetime): return obj.isoformat()
        if isinstance(obj, bytes): return obj.decode('utf-8', errors='ignore')
        if isinstance(obj, Binary): return base64.b64encode(bytes(obj)).decode()
        if isinstance(obj, dict):
            return {k: _to_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_to_serializable(v) for v in obj]
        return obj
    except Exception:
        return str(obj)

@app.route('/api/download/database/<db>', methods=['GET'])
@auth_required
def download_database_zip(db):
    c, uri, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        tmp = _temp_zip()
        _schedule_temp_cleanup(tmp)
        manifest = {'database': db, 'exported_at': datetime.datetime.utcnow().isoformat(),
                    'collections': []}
        with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zf:
            for col_name in c[db].list_collection_names():
                try: docs = [_to_serializable(d) for d in c[db][col_name].find({})]
                except Exception as e: docs = [{'__error__': str(e)}]
                fname = _safe_name(col_name) + '.json'
                zf.writestr(fname, json.dumps(docs, indent=2, default=str))
                manifest['collections'].append({
                    'name': col_name, 'documents': len(docs), 'file': fname})
            zf.writestr('_manifest.json', json.dumps(manifest, indent=2))
        log_audit('DOWNLOAD_DB_ZIP', 'user', {'db': db, 'collections': len(manifest['collections'])})
        return send_file(tmp, mimetype='application/zip', as_attachment=True,
                         download_name=f'{_safe_name(db)}_export.zip')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/all-databases', methods=['GET'])
@auth_required
def download_all_databases_zip():
    c, uri, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        tmp = _temp_zip()
        _schedule_temp_cleanup(tmp)
        manifest = {'exported_at': datetime.datetime.utcnow().isoformat(), 'databases': []}
        with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zf:
            for db_name in c.list_database_names():
                if db_name in ('admin', 'local', 'config'): continue
                db_meta = {'name': db_name, 'collections': []}
                try: col_names = c[db_name].list_collection_names()
                except Exception: col_names = []
                for col_name in col_names:
                    try: docs = [_to_serializable(d) for d in c[db_name][col_name].find({})]
                    except Exception as e: docs = [{'__error__': str(e)}]
                    fname = f'{_safe_name(db_name)}/{_safe_name(col_name)}.json'
                    zf.writestr(fname, json.dumps(docs, indent=2, default=str))
                    db_meta['collections'].append({
                        'name': col_name, 'documents': len(docs), 'file': fname})
                manifest['databases'].append(db_meta)
            zf.writestr('_manifest.json', json.dumps(manifest, indent=2))
        log_audit('DOWNLOAD_ALL_DBS_ZIP', 'user', {'total_dbs': len(manifest['databases'])})
        ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        return send_file(tmp, mimetype='application/zip', as_attachment=True,
                         download_name=f'tocxic_all_databases_{ts}.zip')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/collection/<db>/<col>', methods=['GET'])
@auth_required
def download_collection(db, col):
    c, uri, err = _user_client()
    if err: return jsonify({'error': err}), 400
    fmt = (request.args.get('format') or 'json').lower()
    try:
        docs = [_to_serializable(d) for d in c[db][col].find({})]
        ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base_name = f'{_safe_name(db)}_{_safe_name(col)}_{ts}'
        if fmt == 'csv':
            buf = io.StringIO()
            if docs:
                import csv as _csv
                keys = sorted({k for d in docs for k in d.keys()})
                w = _csv.DictWriter(buf, fieldnames=keys)
                w.writeheader()
                for d in docs:
                    w.writerow({k: json.dumps(d.get(k), default=str) if isinstance(d.get(k), (dict, list)) else d.get(k, '') for k in keys})
            return send_file(io.BytesIO(buf.getvalue().encode('utf-8')), mimetype='text/csv',
                             as_attachment=True, download_name=base_name + '.csv')
        if fmt == 'jsonl':
            text = '\n'.join(json.dumps(d, default=str) for d in docs)
            return send_file(io.BytesIO(text.encode()), mimetype='application/x-ndjson',
                             as_attachment=True, download_name=base_name + '.jsonl')
        if fmt == 'zip':
            tmp = _temp_zip()
            _schedule_temp_cleanup(tmp)
            with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(f'{_safe_name(col)}.json', json.dumps(docs, indent=2, default=str))
                zf.writestr('_manifest.json', json.dumps({
                    'database': db, 'collection': col, 'documents': len(docs),
                    'exported_at': datetime.datetime.utcnow().isoformat()
                }, indent=2))
            return send_file(tmp, mimetype='application/zip', as_attachment=True,
                             download_name=base_name + '.zip')
        return send_file(io.BytesIO(json.dumps(docs, indent=2, default=str).encode()),
                         mimetype='application/json', as_attachment=True,
                         download_name=base_name + '.json')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/document/<db>/<col>/<doc_id>', methods=['GET'])
@auth_required
def download_document(db, col, doc_id):
    c, uri, err = _user_client()
    if err: return jsonify({'error': err}), 400
    try:
        doc = None
        try: doc = c[db][col].find_one({'_id': ObjectId(doc_id)})
        except Exception: pass
        if not doc: doc = c[db][col].find_one({'_id': doc_id})
        if not doc: return jsonify({'error': 'Document not found'}), 404
        s = _to_serializable(doc)
        return send_file(io.BytesIO(json.dumps(s, indent=2, default=str).encode()),
                         mimetype='application/json', as_attachment=True,
                         download_name=f'{_safe_name(col)}_{_safe_name(doc_id[:12])}.json')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/gridfs/<bucket>/<file_id>', methods=['GET'])
@auth_required
def download_gridfs_file(bucket, file_id):
    c, uri, err = _user_client()
    if err: return jsonify({'error': err}), 400
    db = request.args.get('db') or 'test'
    try:
        from gridfs import GridFS
        fs = GridFS(c[db], collection=bucket)
        grid_out = fs.get(ObjectId(file_id))
        stream = io.BytesIO(grid_out.read())
        stream.seek(0)
        log_audit('DOWNLOAD_GRIDFS', 'user', {'db': db, 'bucket': bucket, 'file_id': file_id})
        return send_file(stream, mimetype=grid_out.content_type or 'application/octet-stream',
                         as_attachment=True, download_name=grid_out.filename or f'{file_id}.bin')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/master/download/all', methods=['GET'])
@role_required('master', 'grandmaster')
def master_download_all_zip():
    m = get_master_client()
    if not m: return jsonify({'error': 'Master DB unavailable'}), 503
    try:
        tmp = _temp_zip()
        _schedule_temp_cleanup(tmp)
        manifest = {'exported_at': datetime.datetime.utcnow().isoformat(), 'databases': []}
        with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zf:
            for db_name in m.list_database_names():
                if db_name in ('admin', 'local', 'config'): continue
                db_meta = {'name': db_name, 'collections': []}
                try: col_names = m[db_name].list_collection_names()
                except Exception: col_names = []
                for col_name in col_names:
                    try: docs = [_to_serializable(d) for d in m[db_name][col_name].find({})]
                    except Exception as e: docs = [{'__error__': str(e)}]
                    fname = f'{_safe_name(db_name)}/{_safe_name(col_name)}.json'
                    zf.writestr(fname, json.dumps(docs, indent=2, default=str))
                    db_meta['collections'].append({
                        'name': col_name, 'documents': len(docs), 'file': fname})
                manifest['databases'].append(db_meta)
            zf.writestr('_manifest.json', json.dumps(manifest, indent=2))
        log_audit('MASTER_DOWNLOAD_ALL', 'master', {'total_dbs': len(manifest['databases'])})
        ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        return send_file(tmp, mimetype='application/zip', as_attachment=True,
                         download_name=f'tocxic_master_backup_{ts}.zip')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/master/download/collection/<db>/<col>', methods=['GET'])
@role_required('master', 'grandmaster')
def master_download_collection(db, col):
    m = get_master_client()
    if not m: return jsonify({'error': 'Master DB unavailable'}), 503
    fmt = (request.args.get('format') or 'json').lower()
    try:
        docs = [_to_serializable(d) for d in m[db][col].find({})]
        ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base = f'master_{_safe_name(db)}_{_safe_name(col)}_{ts}'
        if fmt == 'csv':
            buf = io.StringIO()
            if docs:
                import csv as _csv
                keys = sorted({k for d in docs for k in d.keys()})
                w = _csv.DictWriter(buf, fieldnames=keys)
                w.writeheader()
                for d in docs:
                    w.writerow({k: json.dumps(d.get(k), default=str) if isinstance(d.get(k), (dict, list)) else d.get(k, '') for k in keys})
            return send_file(io.BytesIO(buf.getvalue().encode()), mimetype='text/csv',
                             as_attachment=True, download_name=base + '.csv')
        return send_file(io.BytesIO(json.dumps(docs, indent=2, default=str).encode()),
                         mimetype='application/json', as_attachment=True,
                         download_name=base + '.json')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════
# MASTER/GM OVERSIGHT
# ═══════════════════════════════════════════════
@app.route('/api/master/dashboard', methods=['GET'])
@role_required('master', 'grandmaster')
def master_dashboard():
    uris = _coll_uris(); audits = _coll_audits(); logins = _coll_logins()
    visits = _coll_visits(); devices = _coll_devices(); master_uris = _coll_master_uris()
    if uris is None: return jsonify({'error': 'Master DB unavailable'}), 503
    return jsonify({
        'total_users': uris.count_documents({}),
        'total_visits': visits.count_documents({}) if visits is not None else 0,
        'total_devices': devices.count_documents({}) if devices is not None else 0,
        'total_audits': audits.count_documents({}) if audits is not None else 0,
        'total_login_attempts': logins.count_documents({}) if logins is not None else 0,
        'total_master_uris': master_uris.count_documents({}) if master_uris is not None else 0,
        'active_sessions': len(SESSIONS),
    }), 200

@app.route('/api/master/visitors', methods=['GET'])
@role_required('master', 'grandmaster')
def master_visitors():
    vsess = _coll_visitor_sess(); devices = _coll_devices()
    if vsess is None and devices is None:
        return jsonify({'error': 'Master DB unavailable'}), 503
    sessions = list(vsess.find({}).sort('last_seen', -1).limit(500)) if vsess is not None else []
    devs = list(devices.find({}).sort('last_seen', -1).limit(500)) if devices is not None else []
    return jsonify({'sessions': [to_json(s) for s in sessions],
                    'devices': [to_json(d) for d in devs]}), 200

@app.route('/api/master/users', methods=['GET'])
@role_required('master', 'grandmaster')
def master_users():
    uris = _coll_uris()
    if uris is None: return jsonify({'error': 'Master DB unavailable'}), 503
    docs = list(uris.find({}).sort('last_used', -1).limit(500))
    return jsonify({'users': [to_json(d) for d in docs]}), 200

@app.route('/api/master/audits', methods=['GET'])
@role_required('master', 'grandmaster')
def master_audits():
    audits = _coll_audits()
    if audits is None: return jsonify({'error': 'Master DB unavailable'}), 503
    docs = list(audits.find({}).sort('timestamp', -1).limit(500))
    return jsonify({'audits': [to_json(d) for d in docs]}), 200

@app.route('/api/master/login-attempts', methods=['GET'])
@role_required('master', 'grandmaster')
def master_login_attempts():
    logins = _coll_logins()
    if logins is None: return jsonify({'error': 'Master DB unavailable'}), 503
    docs = list(logins.find({}).sort('timestamp', -1).limit(500))
    return jsonify({'attempts': [to_json(d) for d in docs]}), 200

@app.route('/api/master/reveal-uri/<vid>', methods=['GET'])
@role_required('master', 'grandmaster')
def master_reveal_uri(vid):
    uris = _coll_uris()
    if uris is None: return jsonify({'error': 'Master DB unavailable'}), 503
    doc = uris.find_one({'vid': vid})
    if not doc: return jsonify({'error': 'Not found'}), 404
    log_audit('REVEAL_URI', 'master', {'target_vid': vid})
    return jsonify({'uri': doc.get('uri'), 'vid': vid}), 200

@app.route('/api/master/storage', methods=['GET'])
@role_required('master', 'grandmaster')
def master_storage():
    m = get_master_client()
    if not m: return jsonify({'error': 'Master DB unavailable'}), 503
    out = {}
    for dbname in m.list_database_names():
        if dbname in ('admin', 'local', 'config'): continue
        try:
            st = m[dbname].command('dbStats')
            out[dbname] = {'size': st.get('dataSize', 0), 'storage': st.get('storageSize', 0),
                           'collections': st.get('collections', 0), 'documents': st.get('objects', 0)}
        except Exception as e: out[dbname] = {'error': str(e)}
    return jsonify({'storage': out}), 200

@app.route('/api/master/device/<device_hash>', methods=['GET'])
@role_required('master', 'grandmaster')
def master_device_detail(device_hash):
    devices = _coll_devices()
    if devices is None: return jsonify({'error': 'Master DB unavailable'}), 503
    doc = devices.find_one({'device_hash': device_hash})
    if not doc: return jsonify({'error': 'Not found'}), 404
    uris = _coll_uris(); linked = []
    if uris is not None and doc.get('vids'):
        for d in uris.find({'vid': {'$in': doc['vids']}}): linked.append(to_json(d))
    log_audit('DEVICE_VIEW', 'master', {'device_hash': device_hash[:12]})
    return jsonify({'device': to_json(doc), 'linked_uris': linked}), 200

@app.route('/api/gm/impersonate/<vid>', methods=['POST'])
@role_required('grandmaster')
def gm_impersonate(vid):
    uris = _coll_uris()
    if uris is None: return jsonify({'error': 'Master DB unavailable'}), 503
    doc = uris.find_one({'vid': vid})
    if not doc: return jsonify({'error': 'User not found'}), 404
    new_vid = f"imp_{uuid.uuid4()}"
    SESSIONS[new_vid] = {'role': 'user', 'uri': doc['uri'], 'impersonating': True,
                         'target_vid': vid, 'created': datetime.datetime.utcnow().isoformat()}
    log_audit('GM_IMPERSONATE', 'grandmaster', {'target_vid': vid})
    return jsonify({'ok': True, 'vid': new_vid, 'role': 'user'}), 200

@app.route('/api/gm/connect/<vid>', methods=['GET'])
@role_required('grandmaster')
def gm_connect(vid):
    uris = _coll_uris()
    if uris is None: return jsonify({'error': 'Master DB unavailable'}), 503
    doc = uris.find_one({'vid': vid})
    if not doc: return jsonify({'error': 'Not found'}), 404
    c, err = get_client_uri(doc['uri'])
    if err: return jsonify({'error': err}), 400
    try: return jsonify({'databases': c.list_database_names()}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/gm/delete-visitor/<ip>', methods=['DELETE'])
@role_required('grandmaster')
def gm_delete_visitor(ip):
    visits = _coll_visits(); vsess = _coll_visitor_sess()
    if visits is None and vsess is None: return jsonify({'error': 'Master DB unavailable'}), 503
    deleted = 0
    if visits is not None: deleted += visits.delete_many({'ip': ip}).deleted_count
    if vsess is not None: deleted += vsess.delete_many({'ip': ip}).deleted_count
    log_audit('GM_DELETE_VISITOR', 'grandmaster', {'ip': ip, 'count': deleted})
    return jsonify({'ok': True, 'deleted': deleted}), 200

@app.route('/api/gm/delete-device/<device_hash>', methods=['DELETE'])
@role_required('grandmaster')
def gm_delete_device(device_hash):
    devices = _coll_devices()
    if devices is None: return jsonify({'error': 'Master DB unavailable'}), 503
    res = devices.delete_many({'device_hash': device_hash})
    log_audit('GM_DELETE_DEVICE', 'grandmaster', {'device_hash': device_hash, 'count': res.deleted_count})
    return jsonify({'ok': True, 'deleted': res.deleted_count}), 200

@app.route('/api/gm/delete-user/<vid>', methods=['DELETE'])
@role_required('grandmaster')
def gm_delete_user(vid):
    uris = _coll_uris()
    if uris is None: return jsonify({'error': 'Master DB unavailable'}), 503
    res = uris.delete_many({'vid': vid})
    try:
        if vid in SESSIONS: del SESSIONS[vid]
    except Exception: pass
    log_audit('GM_DELETE_USER', 'grandmaster', {'vid': vid})
    return jsonify({'ok': True, 'deleted': res.deleted_count}), 200

@app.route('/api/gm/wipe/<collection>', methods=['POST'])
@role_required('grandmaster')
def gm_wipe(collection):
    allowed = {'uris': _coll_uris, 'visits': _coll_visits, 'sessions': _coll_visitor_sess,
               'devices': _coll_devices, 'audits': _coll_audits, 'login_attempts': _coll_logins,
               'master_uris': _coll_master_uris}
    if collection not in allowed: return jsonify({'error': 'Invalid collection'}), 400
    if parse_json_body().get('confirm') != collection: return jsonify({'error': 'Confirmation mismatch'}), 400
    coll = allowed[collection]()
    if coll is None: return jsonify({'error': 'Master DB unavailable'}), 503
    res = coll.delete_many({})
    log_audit('GM_WIPE', 'grandmaster', {'collection': collection, 'count': res.deleted_count})
    return jsonify({'ok': True, 'deleted': res.deleted_count}), 200

@app.route('/api/util/ip', methods=['GET'])
@role_required('master', 'grandmaster')
def util_ip():
    ip = request.args.get('ip') or _client_ip()
    if not ip: return jsonify({'error': 'No IP'}), 400
    return jsonify(_ip_lookup(ip)), 200

@app.route('/api/util/pincode', methods=['GET'])
@role_required('master', 'grandmaster')
def util_pincode():
    code = (request.args.get('code') or '').strip()
    if not re.match(r'^\d{6}$', code):
        return jsonify({'error': 'Invalid PIN code — must be 6 digits (India)'}), 400
    return jsonify(_http_get(PINCODE_API + urllib.parse.quote(code), timeout=8)), 200

@app.route('/api/util/zip', methods=['GET'])
@role_required('master', 'grandmaster')
def util_zip_alias():
    return util_pincode()

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'ts': datetime.datetime.utcnow().isoformat(),
                    'master_db': bool(get_master_client())}), 200

@app.errorhandler(404)
def nf(e):
    if request.path.startswith('/api/'): return jsonify({'error': 'Not found'}), 404
    return render_template_string('''<!DOCTYPE html><html><head><title>·</title>
    <style>body{background:#000a0f;color:#3d6d61;font-family:'JetBrains Mono',monospace;
    display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;flex-direction:column;}
    h1{color:#FF3B5C;font-size:72px;margin:0;text-shadow:0 0 30px rgba(255,34,85,.6);}
    p{letter-spacing:3px;text-transform:uppercase;font-size:12px;}</style></head>
    <body><h1>404</h1><p>The void has no such path.</p></body></html>'''), 404

@app.errorhandler(500)
def se(e):
    if request.path.startswith('/api/'): return jsonify({'error': 'Internal server error'}), 500
    return jsonify({'error': 'Internal server error'}), 500

# ═══════════════════════════════════════════════
# DASHBOARD HTML
# ═══════════════════════════════════════════════
DASHBOARD_HTML = r'''<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,viewport-fit=cover">
<title>TOCXIC — Dashboard</title>
<meta name="robots" content="noindex,nofollow,noarchive">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🥭</text></svg>"/>
<style>''' + GLOBAL_CSS + r'''</style></head><body>
<div id="void-shield"></div>
<div class="scanlines"></div>
<div id="alertBox" class="alert"></div>
<div class="app">
<aside class="sidebar" id="sidebar">
  <div class="brand"><div class="brand-logo">🥭</div>
    <div style="min-width:0;flex:1;"><div class="brand-name">TOCXIC</div><div class="brand-sub">Void Grade</div></div></div>
  <div class="side-role"><div class="dot user" id="roleDot"></div>
    <span class="label">Role</span><span class="value" id="roleValue">USER</span></div>
  <div class="nav" id="nav"></div>
</aside>
<div class="side-backdrop" id="sideBackdrop" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('on')"></div>
<main class="main">
  <div class="topbar">
    <div style="display:flex;align-items:center;gap:10px;min-width:0;flex:1;">
      <div class="menu-toggle" onclick="toggleSidebar()">☰</div>
      <div style="min-width:0;flex:1;"><div class="page-title" id="pageTitle">Dashboard</div>
        <div class="page-sub" id="pageSub">Welcome</div></div>
    </div>
    <div class="topbar-right">
      <span class="badge user" id="topBadge">USER</span>
      <button class="btn ghost sm" onclick="logout()">Logout</button>
    </div>
  </div>
  <div class="content" id="content"></div>
</main>
</div>
<script>
const VID = localStorage.getItem('vid');
const ROLE = localStorage.getItem('role') || 'user';
let cachedDbs=[],cachedVisitors=[],cachedUsers=[],cachedMasterUris=[],termDb='test';

function toggleSidebar(){
  const s=document.getElementById('sidebar');const b=document.getElementById('sideBackdrop');
  s.classList.toggle('open');b.classList.toggle('on', s.classList.contains('open'));
}
function H(){return {'Content-Type':'application/json','X-Session-ID':VID||''};}
function showAlert(m,t,d){
  t=t||'info';d=d||7000;
  const b=document.getElementById('alertBox');
  b.textContent=m;b.className='alert show '+t;
  setTimeout(function(){b.className='alert';},d);
}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function fmt(b){b=Number(b)||0;if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';if(b<1073741824)return (b/1048576).toFixed(1)+' MB';return (b/1073741824).toFixed(2)+' GB';}
function setContent(html){var e=document.getElementById('content');if(e)e.innerHTML=html;}
function setEl(id, html){var e=document.getElementById(id);if(e)e.innerHTML=html;}
function setTxt(id, txt){var e=document.getElementById(id);if(e)e.textContent=txt;}

async function downloadBlob(url, fallbackName){
  try{
    showAlert('⏳ Preparing download...', 'info', 2000);
    const res = await fetch(url, { headers: H(), credentials: 'include' });
    if(!res.ok){
      let t = '';
      try{ t = await res.text(); }catch(e){}
      showAlert('❌ Download failed (' + res.status + '): ' + t.slice(0,180), 'error');
      return;
    }
    let fname = fallbackName || 'download';
    const cd = res.headers.get('Content-Disposition') || '';
    const m = cd.match(/filename\*?=(?:UTF-8'')?["']?([^"';\n]+)/i);
    if(m && m[1]) fname = decodeURIComponent(m[1].replace(/["']/g, ''));
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = fname;
    document.body.appendChild(a);
    a.click();
    setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 400);
    showAlert('✅ Download started: ' + fname, 'success', 2500);
  }catch(e){
    showAlert('Download error: ' + e.message, 'error');
  }
}

function logout(){
  localStorage.clear();
  try{ document.cookie = 'vid=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'; }catch(e){}
  location.href = (ROLE === 'user') ? '/' : '/superadmin';
}
async function api(path,opts){
  const res=await fetch(path,Object.assign({headers:H(),credentials:'include'},opts||{}));
  const j=await res.json().catch(function(){return {error:'bad json'};});
  if(!res.ok)throw new Error(j.error||('HTTP '+res.status));
  return j;
}
async function apiBody(path,body,method){
  method=method||'POST';
  return api(path,{method:method,body:JSON.stringify(body||{})});
}
function empty(ico,msg){return '<div class="empty"><span class="ico">'+ico+'</span><div class="msg">'+esc(msg)+'</div></div>';}
function ipBtn(ip){return '<button class="btn checkip" onclick="lookupIp(\''+esc(ip)+'\')">🔍 CHECK IP</button>';}

const NAVS = {
  user: [
    {sec:'Data'},
    {id:'mystorage', ico:'💾', label:'My Storage'},
    {id:'databases', ico:'🗄', label:'Databases'},
    {id:'collections', ico:'📁', label:'Collections'},
    {id:'docs', ico:'📝', label:'Documents'},
    {id:'agg', ico:'🔗', label:'Aggregation'},
    {id:'gridfs', ico:'📦', label:'GridFS'},
    {id:'terminal', ico:'💻', label:'Shell'},
    {sec:'Security'},
    {id:'users_roles', ico:'🔐', label:'Users & Roles'},
    {id:'sessions', ico:'👻', label:'Sessions'},
    {sec:'Insights'},
    {id:'monitor', ico:'📡', label:'Monitor'},
    {id:'metrics', ico:'📈', label:'Metrics'},
    {id:'profiler', ico:'🔬', label:'Profiler'},
    {id:'explain', ico:'⚡', label:'Query Planner'},
    {id:'changes', ico:'🔥', label:'Change Streams'},
    {id:'repl', ico:'🌐', label:'Replication'},
    {id:'server', ico:'🛰', label:'Server Info'},
    {id:'top', ico:'📊', label:'Top Ops'},
    {id:'logs', ico:'📋', label:'Logs / Cluster'},
    {sec:'Advanced'},
    {id:'dbstats', ico:'📊', label:'DB Stats'},
    {id:'colstats', ico:'📈', label:'Collection Stats'},
    {id:'indexes', ico:'🔖', label:'Indexes'},
    {id:'text', ico:'🔎', label:'Text Search'},
    {id:'distinct', ico:'🎯', label:'Distinct'},
    {id:'fam', ico:'✏️', label:'Find & Modify'},
    {id:'bulk', ico:'⚙️', label:'Bulk Write'},
    {sec:'Tools'},
    {id:'downloads', ico:'⬇', label:'Downloads'},
    {id:'mask', ico:'🎭', label:'Data Masking'},
    {id:'io', ico:'📥', label:'Import / Export'},
    {id:'backup', ico:'💾', label:'Backup'},
    {sec:'Danger'},
    {id:'danger', ico:'⚠️', label:'Danger Zone'},
    {id:'advanced_cmd', ico:'💥', label:'Advanced Commands'},
    {sec:'☠ IRREVERSIBLE'},
    {id:'format', ico:'💥', label:'FORMAT MONGODB'}
  ],
  master: [
    {sec:'Overview'},
    {id:'master', ico:'📊', label:'Dashboard'},
    {sec:'My Clusters'},
    {id:'myclusters', ico:'🔗', label:'URI Vault'},
    {id:'mystorage', ico:'💾', label:'Cluster Storage'},
    {id:'databases', ico:'🗄', label:'Databases'},
    {id:'collections', ico:'📁', label:'Collections'},
    {id:'docs', ico:'📝', label:'Documents'},
    {id:'agg', ico:'🔗', label:'Aggregation'},
    {id:'gridfs', ico:'📦', label:'GridFS'},
    {id:'terminal', ico:'💻', label:'Shell'},
    {sec:'Monitoring'},
    {id:'visitors', ico:'👥', label:'Visitors & Devices'},
    {id:'users', ico:'🔑', label:'Connected Users'},
    {id:'logins', ico:'🔐', label:'Login Attempts'},
    {id:'audits', ico:'📜', label:'Audit Trail'},
    {id:'storage', ico:'💾', label:'Master Storage'},
    {sec:'Tools'},
    {id:'downloads', ico:'⬇', label:'Downloads'},
    {sec:'Security'},
    {id:'gmcreds', ico:'🔑', label:'My Credentials'},
    {sec:'Restricted'},
    {id:'utils', ico:'🌐', label:'IP / PIN Lookup'},
    {sec:'Owner'},
    {id:'owner_console', ico:'👑', label:'Owner Console'}
  ],
  grandmaster: [
    {sec:'Overview'},
    {id:'master', ico:'📊', label:'Dashboard'},
    {sec:'My Clusters'},
    {id:'myclusters', ico:'🔗', label:'URI Vault'},
    {id:'mystorage', ico:'💾', label:'Cluster Storage'},
    {id:'databases', ico:'🗄', label:'Databases'},
    {id:'collections', ico:'📁', label:'Collections'},
    {id:'docs', ico:'📝', label:'Documents'},
    {id:'agg', ico:'🔗', label:'Aggregation'},
    {id:'gridfs', ico:'📦', label:'GridFS'},
    {id:'terminal', ico:'💻', label:'Shell'},
    {sec:'Monitoring'},
    {id:'visitors', ico:'👥', label:'Visitors & Devices'},
    {id:'users', ico:'🔑', label:'Connected Users'},
    {id:'logins', ico:'🔐', label:'Login Attempts'},
    {id:'audits', ico:'📜', label:'Audit Trail'},
    {id:'storage', ico:'💾', label:'Master Storage'},
    {sec:'Tools'},
    {id:'downloads', ico:'⬇', label:'Downloads'},
    {sec:'Security'},
    {id:'gmcreds', ico:'🔑', label:'My Credentials'},
    {sec:'Override'},
    {id:'impersonate', ico:'🎭', label:'Impersonate'},
    {id:'wipe', ico:'💀', label:'Wipe Collections'},
    {sec:'Restricted'},
    {id:'utils', ico:'🌐', label:'IP / PIN Lookup'},
    {sec:'Owner'},
    {id:'owner_console', ico:'👑', label:'Owner Console'},
    {sec:'☠ DANGER — IRREVERSIBLE'},
    {id:'format', ico:'💥', label:'FORMAT MONGODB'}
  ]
};

const TITLES = {
  master:'Dashboard', visitors:'Visitors & Devices', users:'Connected Users',
  logins:'Login Attempts', audits:'Audit Trail', storage:'Master Storage',
  impersonate:'Impersonate', wipe:'Wipe Collections',
  mystorage:'Cluster Storage', myclusters:'URI Vault', gmcreds:'My Credentials',
  databases:'Databases', collections:'Collections', docs:'Documents',
  terminal:'MongoDB Shell', monitor:'Live Monitor', metrics:'Metrics',
  profiler:'Profiler', changes:'Change Streams', logs:'Logs & Cluster',
  mask:'Data Masking', io:'Import / Export', backup:'Backup',
  utils:'Restricted · IP / PIN Lookup', danger:'Danger Zone',
  agg:'Aggregation Pipeline', gridfs:'GridFS Files',
  users_roles:'Users & Roles', sessions:'Live Sessions',
  explain:'Query Planner', repl:'Replication Status', server:'Server Info',
  top:'Top Operations', dbstats:'Database Stats', colstats:'Collection Stats',
  indexes:'Indexes', text:'Text Search', distinct:'Distinct Values',
  fam:'Find & Modify', bulk:'Bulk Write', advanced_cmd:'Advanced Commands',
  downloads:'Downloads',
  owner_console:'Owner Console',
  format:'⚠ FORMAT MONGODB — IRREVERSIBLE'
};
const SUBS = {
  master:'System overview', visitors:'Who visited your app',
  users:'Users who connected', logins:'Authentication events',
  audits:'All system actions', storage:'All databases on master cluster',
  mystorage:'Storage for the currently-active cluster',
  myclusters:'Manage multiple MongoDB URIs',
  gmcreds:'Change username, password, or bypass key',
  databases:'Your MongoDB databases', collections:'Collections',
  docs:'CRUD documents', terminal:'Run MongoDB commands',
  monitor:'Server metrics', metrics:'Opcounters & latency',
  profiler:'Running & slow queries', changes:'Real-time events',
  logs:'Server log', mask:'Anonymize PII', io:'Bulk data transfer',
  backup:'mongodump', utils:'Master & GM only', danger:'Destructive operations',
  agg:'Build aggregation pipelines', gridfs:'File storage over MongoDB',
  users_roles:'Database users and custom roles', sessions:'List, kill, or clear sessions',
  explain:'Analyze query performance', repl:'Replica set members & oplog',
  server:'buildInfo, hostInfo, cmdline', top:'Top collection operations',
  dbstats:'dbStats breakdown', colstats:'collStats breakdown',
  indexes:'List, create, drop, stats', text:'$text full-text search',
  distinct:'Unique field values', fam:'findOneAndUpdate/Delete',
  bulk:'bulkWrite many ops', advanced_cmd:'validate / reIndex / compact',
  downloads:'Export databases, collections, documents',
  owner_console:'Full owner control: users, logins, audits, sessions, password',
  format:'Drops EVERY non-system database. Cannot be undone.'
};

function buildNav(){
  const list = NAVS[ROLE] || NAVS.user;
  document.getElementById('nav').innerHTML = list.map(function(n){
    if(n.sec) return '<div class="nav-section">'+n.sec+'</div>';
    return '<div class="nav-item" data-tab="'+n.id+'" onclick="switchTab(\''+n.id+'\')"><span class="ico">'+n.ico+'</span>'+n.label+'</div>';
  }).join('');
  const firstPanel = list.find(function(n){return n.id;});
  switchTab(firstPanel.id);
}

function switchTab(id){
  document.querySelectorAll('.nav-item').forEach(function(n){
    n.classList.toggle('active', n.dataset.tab === id);
  });
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sideBackdrop').classList.remove('on');
  document.getElementById('pageTitle').textContent = TITLES[id] || id;
  document.getElementById('pageSub').textContent = SUBS[id] || '';
  const fn = window['render_'+id];
  if(typeof fn === 'function') return fn();
  setContent('<div class="card">'+empty('🚧','Panel: '+id)+'</div>');
}

function render_downloads(){
  setContent(
    '<div class="card" style="border-color:rgba(0,237,100,.4);">' +
      '<div class="card-title"><span class="ico">⬇</span>Download Center' +
        '<span class="badge user" style="margin-left:auto;">'+ROLE.toUpperCase()+'</span></div>' +
      '<div class="hint">Export database, collection, document, GridFS files. ZIP / JSON / CSV.</div>' +
      '<div class="grid cols-2">' +
        '<div class="stat blue" style="cursor:pointer;" onclick="downloadAllDbsZip()">' +
          '<span class="num">📦</span><span class="lbl">All Databases · ZIP</span>' +
        '</div>' +
        (ROLE !== 'user'
          ? '<div class="stat red" style="cursor:pointer;" onclick="downloadMasterAll()">' +
              '<span class="num">💾</span><span class="lbl">Master Cluster · ZIP</span>' +
            '</div>'
          : '<div class="stat amber" style="cursor:pointer;" onclick="switchTab(\'backup\')">' +
              '<span class="num">🛠</span><span class="lbl">mongodump</span>' +
            '</div>') +
      '</div>' +
    '</div>' +
    '<div class="card">' +
      '<div class="card-title"><span class="ico">🗄</span>Per-Database Export</div>' +
      '<div id="dlDbList"></div>' +
    '</div>' +
    '<div class="card">' +
      '<div class="card-title"><span class="ico">📁</span>Per-Collection Export</div>' +
      '<div class="row">' +
        '<select class="select grow" id="dlDbSel"></select>' +
        '<select class="select grow" id="dlColSel"></select>' +
      '</div>' +
      '<div class="row">' +
        '<button class="btn primary" onclick="dlColFromSelect(\'json\')">⬇ JSON</button>' +
        '<button class="btn primary" onclick="dlColFromSelect(\'csv\')">⬇ CSV</button>' +
        '<button class="btn primary" onclick="dlColFromSelect(\'jsonl\')">⬇ JSONL</button>' +
        '<button class="btn green" onclick="dlColFromSelect(\'zip\')">⬇ ZIP</button>' +
      '</div>' +
    '</div>'
  );
  loadDlDbList();
  loadDbsForSelect('dlDbSel', function(){loadColsForSelect('dlDbSel','dlColSel');});
}
async function loadDlDbList(){
  try{
    const j = await api('/api/user/databases');cachedDbs=j.databases||[];
    const el=document.getElementById('dlDbList');
    if(!el) return;
    if(!cachedDbs.length){el.innerHTML=empty('🗄','No databases');return;}
    el.innerHTML = '<div class="table-wrap"><table><thead><tr>' +
      '<th>Database</th><th>Collections</th><th>Documents</th><th>Size</th><th>Export</th>' +
      '</tr></thead><tbody>' +
      cachedDbs.map(function(d){
        const n=esc(d.name);
        return '<tr><td><strong>'+n+'</strong></td>' +
          '<td>'+(d.collections||0)+'</td><td>'+(d.documents||0)+'</td><td>'+fmt(d.size||0)+'</td>' +
          '<td><button class="btn green sm" onclick="downloadDbZip(\''+n+'\')">⬇ ZIP</button></td></tr>';
      }).join('') + '</tbody></table></div>';
  }catch(e){showAlert('DL: '+e.message,'error');}
}
function downloadDbZip(name){
  downloadBlob('/api/download/database/'+encodeURIComponent(name), name+'_export.zip');
}
function downloadAllDbsZip(){
  if(!confirm('Download ALL databases as one ZIP?')) return;
  downloadBlob('/api/download/all-databases', 'tocxic_all_databases.zip');
}
function downloadMasterAll(){
  if(!confirm('Download ENTIRE master cluster as ZIP?')) return;
  downloadBlob('/api/master/download/all', 'tocxic_master_backup.zip');
}
function dlCol(db,col,fmt){
  const ext = fmt==='csv'?'.csv':(fmt==='jsonl'?'.jsonl':(fmt==='zip'?'.zip':'.json'));
  downloadBlob('/api/download/collection/'+encodeURIComponent(db)+'/'+encodeURIComponent(col)+'?format='+fmt, db+'_'+col+ext);
}
function dlColFromSelect(fmt){
  const db=document.getElementById('dlDbSel').value;
  const col=document.getElementById('dlColSel').value;
  if(!db||!col){showAlert('Pick db + collection','error');return;}
  dlCol(db,col,fmt);
}
function dlDoc(db,col,id){
  downloadBlob('/api/download/document/'+encodeURIComponent(db)+'/'+encodeURIComponent(col)+'/'+encodeURIComponent(id), col+'_'+String(id).slice(0,12)+'.json');
}
function dlGfs(fid){
  const db=document.getElementById('gfsDb').value;
  const bucket=document.getElementById('gfsBucket').value;
  downloadBlob('/api/download/gridfs/'+encodeURIComponent(bucket)+'/'+encodeURIComponent(fid)+'?db='+encodeURIComponent(db), String(fid)+'.bin');
}
function dlMasterDb(db){
  downloadBlob('/api/download/database/'+encodeURIComponent(db), db+'_export.zip');
}

function render_owner_console(){
  setContent(
    '<div class="card" style="border-color:rgba(255,34,85,.4);">' +
      '<div class="card-title"><span class="ico" style="color:#FF2255;">👑</span>Owner Console' +
        '<span class="badge restricted" style="margin-left:auto;">MASTER / GM ONLY</span></div>' +
      '<div class="hint">' +
        'Full owner control panel: Users, Login Attempts, Owner Logins, Audit Log, Live Sessions, Change Password. ' +
        'Delete rows, purge entire collections, change the owner password. Everything.' +
      '</div>' +
      '<button class="btn primary full" style="margin-top:18px;padding:18px;font-size:15px;font-weight:900;" ' +
        'onclick="window.open(\'/superadmin/owner-panel\',\'_blank\')">🛡 OPEN OWNER CONSOLE →</button>' +
      '<div class="hint" style="margin-top:14px;">Opens in a new tab — uses your current superadmin session automatically.</div>' +
    '</div>'
  );
}

function render_format(){
  setContent(
    '<div class="card" style="border:2px solid #FF2255;box-shadow:0 0 60px rgba(255,34,85,.35);">' +
      '<div class="card-title"><span class="ico" style="color:#FF2255;font-size:20px;">💥</span>' +
        '<span style="color:#FF2255;font-size:16px;">FORMAT MONGODB</span>' +
        '<span class="badge restricted" style="margin-left:auto;">IRREVERSIBLE</span></div>' +
      '<div class="hint danger" style="font-size:14px;line-height:1.9;padding:18px;">' +
        '⚠️ <strong>DANGER — READ CAREFULLY</strong><br><br>' +
        'This will <strong style="color:#FF3B5C;">PERMANENTLY DELETE</strong> every database, every collection, ' +
        'every document, every index, and every GridFS file from your connected MongoDB cluster.<br><br>' +
        'Databases <code>admin</code>, <code>local</code>, and <code>config</code> are <strong>protected</strong> and will be skipped.<br><br>' +
        '<strong style="color:#FF3B5C;">THIS CANNOT BE UNDONE.</strong> There is no recycle bin. There is no backup. ' +
        'Once it runs, the data is gone forever.' +
      '</div>' +
      '<div class="field" style="margin-top:20px;">' +
        '<label style="color:#FF3B5C;font-size:12px;letter-spacing:2px;">Type exactly: FORMAT ALL</label>' +
        '<input class="input" id="fmtConfirm" placeholder="FORMAT ALL" autocomplete="off" ' +
          'style="border-color:#FF2255;font-size:15px;text-align:center;letter-spacing:3px;font-weight:900;">' +
      '</div>' +
      '<button class="btn danger full" style="font-size:16px;padding:20px;margin-top:8px;letter-spacing:2px;font-weight:900;" ' +
        'onclick="doFormatAll()">💥 FORMAT ALL DATABASES NOW</button>' +
      '<div class="code" id="fmtOut" style="margin-top:20px;display:none;"></div>' +
    '</div>'
  );
}
async function doFormatAll(){
  const inp = document.getElementById('fmtConfirm');
  const out = document.getElementById('fmtOut');
  const conf = (inp.value || '').trim();
  if(conf !== 'FORMAT ALL'){
    showAlert('❌ Type exactly: FORMAT ALL', 'error', 4000);
    return;
  }
  if(!confirm('⚠⚠⚠ FINAL WARNING ⚠⚠⚠\n\nThis WILL DELETE EVERYTHING on the connected cluster.\n\nProceed?')) return;
  if(!confirm('LAST CHANCE — really continue?\n\nThere is NO undo.')) return;
  out.style.display = 'block';
  out.textContent = '⏳ Formatting... please wait, do NOT close this tab.';
  try{
    const j = await apiBody('/api/user/format-all', { confirm: conf });
    out.textContent =
      '✅ FORMAT COMPLETE\n\n' +
      'Dropped ' + (j.total_dropped||0) + ' databases:\n' +
      (j.dropped || []).map(function(n){ return '  • ' + n; }).join('\n') +
      ((j.errors && j.errors.length) ? '\n\n⚠ Errors:\n' + JSON.stringify(j.errors, null, 2) : '');
    showAlert('✅ Formatted ' + (j.total_dropped||0) + ' databases', 'success', 6000);
    inp.value = '';
  }catch(e){
    out.textContent = '❌ ERROR: ' + e.message;
    showAlert('Format failed: ' + e.message, 'error', 6000);
  }
}

function render_gmcreds(){
  setContent(
    '<div class="card" style="border-color:rgba(255,34,85,.4);">' +
      '<div class="card-title"><span class="ico" style="color:#FF3B5C;">🔑</span>Credential Manager' +
        '<span class="badge restricted" style="margin-left:auto;">' + ROLE.toUpperCase() + '</span></div>' +
      '<div class="hint danger">⚠ Changes take effect immediately.</div>' +
      '<div id="credCurrent" class="code" style="margin-bottom:16px;"></div>' +
    '</div>' +
    '<div class="card">' +
      '<div class="card-title"><span class="ico">✏️</span>Update Credentials</div>' +
      '<div class="field"><label>Current Password OR Bypass Key *</label>' +
        '<input class="input" id="credCurrentVal" type="password" autocomplete="off"></div>' +
      '<div class="grid cols-2">' +
        '<div class="field"><label>New Username (optional)</label>' +
          '<input class="input" id="credNewUser" autocomplete="off"></div>' +
        '<div class="field"><label>New Password (optional)</label>' +
          '<input class="input" id="credNewPwd" type="password" autocomplete="off"></div>' +
      '</div>' +
      '<div class="field"><label>New Bypass Key (optional, ≥16)</label>' +
        '<input class="input" id="credNewKey" autocomplete="off"></div>' +
      '<div class="row">' +
        '<button class="btn primary" onclick="saveCreds()">💾 Save</button>' +
        '<button class="btn ghost" onclick="loadCreds()">↻ Refresh</button>' +
        '<button class="btn danger" onclick="resetCreds()">↺ Reset</button>' +
      '</div>' +
      '<div class="code" id="credOut" style="margin-top:16px;display:none;"></div>' +
    '</div>'
  );
  loadCreds();
}
async function loadCreds(){
  try{
    const j = await api('/api/gm/credentials');
    setTxt('credCurrent',
      '═══ GM ═══\nUsername:    ' + (j.username || '—') + '\nBypass Key:  ' + (j.bypass_key_masked || '—') +
      '\n\n═══ MASTER ═══\n(Login email/password)');
  }catch(e){setTxt('credCurrent', '⚠ ' + e.message);}
}
async function saveCreds(){
  const cur=document.getElementById('credCurrentVal').value;
  const nu=document.getElementById('credNewUser').value.trim();
  const np=document.getElementById('credNewPwd').value;
  const nk=document.getElementById('credNewKey').value.trim();
  const out=document.getElementById('credOut');out.style.display='block';
  if(!cur){out.textContent='⚠ Current required';return;}
  if(!nu&&!np&&!nk){out.textContent='⚠ Provide one new value';return;}
  if(!confirm('Save changes? Old creds stop working.')) return;
  out.textContent='Saving...';
  try{
    const j = await apiBody('/api/gm/credentials/update',{current_password:cur,new_username:nu,new_password:np,new_bypass_key:nk});
    out.textContent='✅ Updated: user='+j.username_changed+' pwd='+j.password_changed+' key='+j.key_changed;
    showAlert('✅ Updated','success');loadCreds();
  }catch(e){out.textContent='❌ '+e.message;showAlert(e.message,'error');}
}
async function resetCreds(){
  const cur=prompt('Current password or bypass key:');
  if(!cur)return;
  if(!confirm('Reset to defaults?'))return;
  try{await apiBody('/api/gm/credentials/reset-to-env',{current_password:cur});showAlert('✅ Reset','success');loadCreds();}
  catch(e){showAlert(e.message,'error');}
}

function render_mystorage(){
  setContent('<div class="card"><div class="card-title"><span class="ico">💾</span>Active Cluster Storage' +
    '<button class="btn green sm" style="margin-left:auto;" onclick="downloadAllDbsZip()">⬇ ALL ZIP</button>' +
    '<button class="btn ghost sm" onclick="loadMyStorage()">↻</button></div>' +
    '<div class="hint" id="msUri">Loading...</div>' +
    '<div class="grid cols-4" id="msStats">'+empty('⏳','Loading...')+'</div></div>' +
    '<div class="card"><div class="card-title">Per-Database Breakdown</div>' +
    '<div class="table-wrap"><table><thead><tr>' +
    '<th>Database</th><th>Collections</th><th>Docs</th><th>Indexes</th><th>Size</th><th>Storage</th><th>Export</th>' +
    '</tr></thead><tbody id="msRows"><tr><td colspan="7">'+empty('⏳','Loading...')+'</td></tr></tbody></table></div></div>');
  loadMyStorage();
}
async function loadMyStorage(){
  const hasDom = function(){ return document.getElementById('msStats') !== null; };
  if(ROLE !== 'user'){
    try{
      const me = await api('/api/me');
      if(!hasDom()) return;
      const vault = await api('/api/master/uris');
      cachedMasterUris = vault.uris || [];
      if(!hasDom()) return;
      if(!cachedMasterUris.length){
        setEl('msUri', '⚠ No active cluster. Add one in URI Vault.');
        setEl('msStats', empty('🔗','No active cluster'));
        setEl('msRows', '<tr><td colspan="7">'+empty('🔗','No data')+'</td></tr>');
        return;
      }
      let active = cachedMasterUris.find(function(u){return me.active_master_uri && u.masked_uri === me.active_master_uri;});
      if(!active){ await apiBody('/api/master/uris/'+cachedMasterUris[0]._id+'/activate',{}); active = cachedMasterUris[0]; }
      if(!hasDom()) return;
      window._activeUriId = active._id;
      const st = await api('/api/master/uris/'+active._id+'/storage');
      if(!hasDom()) return;
      setEl('msUri', '🟢 Active: <strong style="color:#00ED64;">'+esc(st.label||'')+'</strong> · <span class="mono muted">'+esc(st.masked_uri||'')+'</span>');
      const t = st.total || {};
      setEl('msStats',
        '<div class="stat"><span class="num">'+fmt(t.storage||0)+'</span><span class="lbl">Storage</span></div>' +
        '<div class="stat blue"><span class="num">'+fmt(t.size||0)+'</span><span class="lbl">Data</span></div>' +
        '<div class="stat amber"><span class="num">'+(t.collections||0)+'</span><span class="lbl">Collections</span></div>' +
        '<div class="stat purple"><span class="num">'+(t.documents||0).toLocaleString()+'</span><span class="lbl">Documents</span></div>');
      setEl('msRows', (st.databases||[]).map(function(d){
        const n=esc(d.name);
        return '<tr><td><strong>'+n+'</strong></td>' +
          '<td>'+(d.collections||0)+'</td><td>'+(d.documents||0).toLocaleString()+'</td>' +
          '<td>'+(d.indexes||0)+'</td><td>'+fmt(d.size||0)+'</td>' +
          '<td>'+fmt(d.storage||0)+'</td>' +
          '<td><button class="btn green sm" onclick="dlMasterDb(\''+n+'\')">⬇ ZIP</button></td></tr>';
      }).join('') || '<tr><td colspan="7">'+empty('💾','No databases')+'</td></tr>');
    }catch(e){ if(hasDom()) showAlert('Storage: '+e.message,'error'); }
    return;
  }
  try{
    const j = await api('/api/user/storage');
    if(!hasDom()) return;
    setEl('msUri', '🟢 Connected: <span class="mono muted">'+esc(j.masked_uri||'')+'</span>');
    const t = j.total || {};
    setEl('msStats',
      '<div class="stat"><span class="num">'+fmt(t.storage||0)+'</span><span class="lbl">Storage</span></div>' +
      '<div class="stat blue"><span class="num">'+fmt(t.size||0)+'</span><span class="lbl">Data</span></div>' +
      '<div class="stat amber"><span class="num">'+(t.collections||0)+'</span><span class="lbl">Collections</span></div>' +
      '<div class="stat purple"><span class="num">'+(t.documents||0).toLocaleString()+'</span><span class="lbl">Documents</span></div>');
    setEl('msRows', (j.databases||[]).map(function(d){
      const n=esc(d.name);
      return '<tr><td><strong>'+n+'</strong></td>' +
        '<td>'+(d.collections||0)+'</td><td>'+(d.documents||0).toLocaleString()+'</td>' +
        '<td>'+(d.indexes||0)+'</td><td>'+fmt(d.size||0)+'</td>' +
        '<td>'+fmt(d.storage||0)+'</td>' +
        '<td><button class="btn green sm" onclick="downloadDbZip(\''+n+'\')">⬇ ZIP</button></td></tr>';
    }).join('') || '<tr><td colspan="7">'+empty('💾','No databases')+'</td></tr>');
  }catch(e){ if(hasDom()) showAlert('Storage: '+e.message,'error'); }
}

function render_myclusters(){
  setContent('<div class="card"><div class="card-title"><span class="ico">➕</span>Add MongoDB Cluster</div>' +
    '<div class="row"><input class="input grow" id="vaultLabel" placeholder="label">' +
    '<input class="input grow" id="vaultUri" placeholder="mongodb+srv://..."></div>' +
    '<button class="btn primary" onclick="addVaultUri()">🔗 Add</button></div>' +
    '<div class="card"><div class="card-title"><span class="ico">🔗</span>URI Vault' +
    '<button class="btn ghost sm" style="margin-left:auto;" onclick="loadVault()">↻</button></div>' +
    '<div id="vaultList"></div></div>');
  loadVault();
}
async function loadVault(){
  try{
    const j = await api('/api/master/uris');
    cachedMasterUris = j.uris || [];
    const me = await api('/api/me');
    const el = document.getElementById('vaultList');
    if(!el) return;
    if(!cachedMasterUris.length){el.innerHTML=empty('🔗','No clusters yet');return;}
    el.innerHTML = '<div class="table-wrap"><table><thead><tr>' +
      '<th>Label</th><th>URI</th><th>DBs</th><th>Status</th><th>Actions</th>' +
      '</tr></thead><tbody>' +
      cachedMasterUris.map(function(u){
        const isActive = u.masked_uri === me.active_master_uri;
        return '<tr><td><strong>'+esc(u.label||'—')+'</strong></td>' +
          '<td class="mono muted">'+esc(u.masked_uri||'')+'</td>' +
          '<td><span class="pill">'+(u.db_count||0)+'</span></td>' +
          '<td>'+(isActive?'<span class="pill green">ACTIVE</span>':(u.tested_ok?'<span class="pill blue">OK</span>':'<span class="pill red">ERR</span>'))+'</td>' +
          '<td><div class="row" style="margin:0;flex-wrap:wrap;gap:5px;">' +
            (isActive?'':'<button class="btn primary sm" onclick="activateVault(\''+u._id+'\')">▶</button>') +
            '<button class="btn reveal sm" onclick="revealVault(\''+u._id+'\')">🔓</button>' +
            '<button class="btn ghost sm" onclick="testVault(\''+u._id+'\')">🔧</button>' +
            '<button class="btn danger sm" onclick="delVault(\''+u._id+'\')">🗑</button>' +
          '</div></td></tr>';
      }).join('') + '</tbody></table></div>';
  }catch(e){showAlert('Vault: '+e.message,'error');}
}
async function addVaultUri(){
  const label=document.getElementById('vaultLabel').value.trim();
  const uri=document.getElementById('vaultUri').value.trim();
  if(!uri){showAlert('URI required','error');return;}
  try{
    const j=await apiBody('/api/master/uris/add',{label:label,uri:uri});
    showAlert(j.updated?'Updated':'Added','success');
    document.getElementById('vaultLabel').value='';document.getElementById('vaultUri').value='';
    loadVault();
  }catch(e){showAlert(e.message,'error');}
}
async function activateVault(id){
  try{const j=await apiBody('/api/master/uris/'+id+'/activate',{});showAlert('Activated: '+j.label,'success');loadVault();}
  catch(e){showAlert(e.message,'error');}
}
async function revealVault(id){
  try{
    const j=await api('/api/master/uris/'+id+'/reveal');
    const uri=j.uri||'';
    var overlay=document.createElement('div');overlay.className='uri-modal-overlay';
    var inner=document.createElement('div');inner.className='uri-modal';
    inner.innerHTML='<div class="uri-modal-head"><div class="title">🔓 FULL URI — '+esc(j.label||'')+'</div>' +
      '<button class="close-btn" id="vClose">✕ Close</button></div>' +
      '<div class="hint danger">⚠ Contains credentials.</div>' +
      '<textarea readonly id="vText">'+esc(uri)+'</textarea>' +
      '<button id="vCopy" class="btn reveal full" style="margin-top:14px;">📋 Copy URI</button>';
    overlay.appendChild(inner);document.body.appendChild(overlay);
    overlay.querySelector('#vClose').onclick=function(){overlay.remove();};
    overlay.addEventListener('click',function(e){if(e.target===overlay)overlay.remove();});
    overlay.querySelector('#vCopy').onclick=function(){
      const txt=overlay.querySelector('#vText');txt.select();txt.setSelectionRange(0,999999);
      try{
        if(navigator.clipboard) navigator.clipboard.writeText(uri).then(function(){showAlert('✅ Copied','success',3000);}).catch(function(){document.execCommand('copy');showAlert('✅ Copied','success',3000);});
        else{document.execCommand('copy');showAlert('✅ Copied','success',3000);}
      }catch(e){showAlert('Copy failed: '+e.message,'error');}
    };
  }catch(e){showAlert(e.message,'error');}
}
async function testVault(id){
  try{const j=await apiBody('/api/master/uris/'+id+'/test',{});
    if(j.ok)showAlert('✅ OK · '+j.count+' dbs','success');else showAlert('❌ '+j.error,'error');
    loadVault();}
  catch(e){showAlert(e.message,'error');}
}
async function delVault(id){
  if(!confirm('Delete?'))return;
  try{await api('/api/master/uris/'+id,{method:'DELETE'});showAlert('Deleted','success');loadVault();}
  catch(e){showAlert(e.message,'error');}
}

function render_databases(){
  setContent('<div class="card"><div class="card-title"><span class="ico">➕</span>Create Database</div>' +
    '<div class="row"><input class="input grow" id="newDbName" placeholder="my_database">' +
    '<button class="btn primary" onclick="createDb()">Create</button>' +
    '<button class="btn green" onclick="downloadAllDbsZip()">⬇ DOWNLOAD ALL</button>' +
    '<button class="btn ghost" onclick="loadDatabases()">↻</button></div></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Collections</th><th>Documents</th><th>Indexes</th><th>Size</th><th>Actions</th></tr></thead>' +
    '<tbody id="dbRows"><tr><td colspan="6">'+empty('⏳','Loading...')+'</td></tr></tbody></table></div>');
  loadDatabases();
}
async function loadDatabases(){
  try{
    const j = await api('/api/user/databases');cachedDbs=j.databases||[];
    const tb=document.getElementById('dbRows');if(!tb)return;
    if(!cachedDbs.length){tb.innerHTML='<tr><td colspan="6">'+empty('🗄','No databases')+'</td></tr>';return;}
    tb.innerHTML = cachedDbs.map(function(d){
      const n=esc(d.name);
      return '<tr><td><span class="clickable" onclick="useDb(\''+n+'\')">'+n+'</span></td>' +
      '<td>'+(d.collections||0)+'</td><td>'+(d.documents||0)+'</td><td>'+(d.indexes||0)+'</td><td>'+fmt(d.size)+'</td>' +
      '<td><div class="row" style="margin:0;flex-wrap:wrap;gap:5px;">' +
        '<button class="btn ghost sm" onclick="viewDbStats(\''+n+'\')">📊</button>' +
        '<button class="btn green sm" onclick="downloadDbZip(\''+n+'\')">⬇ ZIP</button>' +
        '<button class="btn danger sm" onclick="dropDbByName(\''+n+'\')">Drop</button>' +
      '</div></td></tr>';
    }).join('');
  }catch(e){showAlert('DBs: '+e.message,'error');}
}
async function viewDbStats(db){
  try{const j=await api('/api/user/db/'+encodeURIComponent(db)+'/stats');
    alert('dbStats '+db+':\n\n'+JSON.stringify(j.stats,null,2).slice(0,3000));}
  catch(e){showAlert(e.message,'error');}
}
async function createDb(){const n=document.getElementById('newDbName').value.trim();if(!n)return;
  try{await apiBody('/api/user/database/create',{name:n});showAlert('Created','success');loadDatabases();}
  catch(e){showAlert(e.message,'error');}}
async function dropDbByName(n){if(!confirm('Drop "'+n+'"?'))return;
  try{await apiBody('/api/user/database/drop',{name:n});showAlert('Dropped','success');loadDatabases();}
  catch(e){showAlert(e.message,'error');}}
function useDb(n){switchTab('collections');setTimeout(function(){const s=document.getElementById('colDbSelect');if(s){s.value=n;loadCollections();}},100);}

function render_collections(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📁</span>Collections</div>' +
    '<div class="row"><select class="select grow" id="colDbSelect"></select>' +
    '<input class="input grow" id="newColName" placeholder="new_collection">' +
    '<button class="btn primary" onclick="createCol()">Create</button>' +
    '<button class="btn ghost" onclick="loadCollections()">↻</button></div></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Docs</th><th>Actions</th></tr></thead>' +
    '<tbody id="colRows"><tr><td colspan="4">'+empty('📁','Pick db')+'</td></tr></tbody></table></div>');
  loadDbsForSelect('colDbSelect', loadCollections);
}
async function loadCollections(){
  const db=document.getElementById('colDbSelect')?document.getElementById('colDbSelect').value:'';
  const tb=document.getElementById('colRows');if(!tb)return;
  if(!db){tb.innerHTML='<tr><td colspan="4">'+empty('📁','Pick db')+'</td></tr>';return;}
  try{
    const j=await api('/api/user/db/'+encodeURIComponent(db)+'/collections');
    if(!j.collections || !j.collections.length){tb.innerHTML='<tr><td colspan="4">'+empty('📁','No collections')+'</td></tr>';return;}
    tb.innerHTML = j.collections.map(function(c){
      const dbE=esc(db);const colE=esc(c.name);
      return '<tr><td><span class="clickable" onclick="useCol(\''+dbE+'\',\''+colE+'\')">'+colE+'</span></td>' +
      '<td><span class="pill '+(c.type==='view'?'purple':'green')+'">'+c.type+'</span></td>' +
      '<td>'+c.count+'</td>' +
      '<td><div class="row" style="margin:0;flex-wrap:wrap;gap:5px;">' +
        '<button class="btn ghost sm" onclick="viewColStats(\''+dbE+'\',\''+colE+'\')">📊</button>' +
        '<button class="btn primary sm" onclick="dlCol(\''+dbE+'\',\''+colE+'\',\'json\')">⬇ JSON</button>' +
        '<button class="btn primary sm" onclick="dlCol(\''+dbE+'\',\''+colE+'\',\'csv\')">⬇ CSV</button>' +
        '<button class="btn green sm" onclick="dlCol(\''+dbE+'\',\''+colE+'\',\'zip\')">⬇ ZIP</button>' +
        '<button class="btn ghost sm" onclick="renameCol(\''+dbE+'\',\''+colE+'\')">Rename</button>' +
        '<button class="btn danger sm" onclick="dropCol(\''+dbE+'\',\''+colE+'\')">Drop</button>' +
      '</div></td></tr>';
    }).join('');
  }catch(e){showAlert('Cols: '+e.message,'error');}
}
async function viewColStats(db,col){
  try{const j=await api('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/stats');
    alert('collStats:\n\n'+JSON.stringify(j.stats,null,2).slice(0,3500));}
  catch(e){showAlert(e.message,'error');}
}
async function createCol(){const db=document.getElementById('colDbSelect').value;const n=document.getElementById('newColName').value.trim();if(!db||!n)return;
  try{await apiBody('/api/user/db/'+encodeURIComponent(db)+'/collection/create',{name:n});showAlert('Created','success');loadCollections();}
  catch(e){showAlert(e.message,'error');}}
async function dropCol(db,n){if(!confirm('Drop "'+n+'"?'))return;
  try{await apiBody('/api/user/db/'+encodeURIComponent(db)+'/collection/drop',{name:n});showAlert('Dropped','success');loadCollections();}
  catch(e){showAlert(e.message,'error');}}
async function renameCol(db,old){const n=prompt('New name:',old);if(!n||n===old)return;
  try{await apiBody('/api/user/db/'+encodeURIComponent(db)+'/collection/rename',{old:old,new:n});showAlert('Renamed','success');loadCollections();}
  catch(e){showAlert(e.message,'error');}}
function useCol(db,n){switchTab('docs');setTimeout(function(){const s=document.getElementById('docDbSelect');if(!s)return;s.value=db;
  loadColsForSelect('docDbSelect','docColSelect',function(){const c=document.getElementById('docColSelect');if(c){c.value=n;loadDocs();}});},100);}

function render_docs(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📝</span>Query Documents</div>' +
    '<div class="row"><select class="select grow" id="docDbSelect"></select>' +
    '<select class="select grow" id="docColSelect"></select></div>' +
    '<div class="row"><input class="input grow" id="docFilter" placeholder="filter" value="{}">' +
    '<input class="input" id="docSort" placeholder="sort" style="max-width:140px;">' +
    '<input class="input" id="docLimit" type="number" value="50" style="max-width:80px;">' +
    '<button class="btn primary" onclick="loadDocs()">🔍 Find</button>' +
    '<button class="btn" onclick="insertDoc()">➕ Insert</button>' +
    '<button class="btn green" onclick="dlCurrentCol()">⬇ Export</button></div></div>' +
    '<div id="docList"></div>');
  loadDbsForSelect('docDbSelect', function(){loadColsForSelect('docDbSelect','docColSelect');});
}
function dlCurrentCol(){
  const db=document.getElementById('docDbSelect').value;
  const col=document.getElementById('docColSelect').value;
  if(!db||!col){showAlert('Pick db + collection','error');return;}
  dlCol(db,col,'zip');
}
async function loadDocs(){
  const db=document.getElementById('docDbSelect').value;const col=document.getElementById('docColSelect').value;
  const filter=document.getElementById('docFilter').value||'{}';const sort=document.getElementById('docSort').value||'';
  const limit=document.getElementById('docLimit').value||'50';
  if(!db||!col){showAlert('Pick db + col','error');return;}
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/find',{filter:filter,sort:sort,limit:limit});
    renderDocList(db,col,j.documents||[]);}
  catch(e){showAlert('Find: '+e.message,'error');}
}
function renderDocList(db,col,docs){
  const el=document.getElementById('docList'); if(!el) return;
  if(!docs.length){el.innerHTML='<div class="card">'+empty('📝','No docs')+'</div>';return;}
  el.innerHTML = docs.map(function(d){
    const id=d._id||'';
    const rows=Object.keys(d).filter(function(k){return k!=='_id';}).map(function(k){
      const v=typeof d[k]==='object'&&d[k]!==null?JSON.stringify(d[k]):d[k];
      return '<div class="row" style="margin-bottom:6px;">' +
      '<input class="input" style="flex:0 0 26%;min-width:0;" value="'+esc(k)+'" readonly>' +
      '<input class="input grow" value="'+esc(v)+'"></div>';
    }).join('');
    return '<div class="card" data-doc-id="'+esc(id)+'">' +
    '<div class="row" style="justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px;">' +
    '<span class="mono muted">_id: '+esc(id)+'</span>' +
    '<div class="row" style="margin:0;flex-wrap:wrap;gap:6px;">' +
    '<button class="btn primary sm" onclick="saveDoc(\''+esc(db)+'\',\''+esc(col)+'\',\''+esc(id)+'\',this)">💾 Save</button>' +
    '<button class="btn green sm" onclick="dlDoc(\''+esc(db)+'\',\''+esc(col)+'\',\''+esc(id)+'\')">⬇ JSON</button>' +
    '<button class="btn danger sm" onclick="deleteDoc(\''+esc(db)+'\',\''+esc(col)+'\',\''+esc(id)+'\')">🗑 Delete</button>' +
    '</div></div>'+(rows||'<div class="muted">(empty)</div>')+'</div>';
  }).join('');
}
async function saveDoc(db,col,id,btn){
  const card=btn.closest('.card');const inputs=card.querySelectorAll('input');const obj={};
  for(let i=0;i<inputs.length;i+=2){const k=inputs[i].value;let v=inputs[i+1].value;try{v=JSON.parse(v);}catch(e){}obj[k]=v;}
  try{await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/update',
    {filter:JSON.stringify({_id:id}),update:JSON.stringify(obj)});showAlert('Saved','success');}
  catch(e){showAlert('Save: '+e.message,'error');}
}
async function deleteDoc(db,col,id){if(!confirm('Delete?'))return;
  try{await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/delete',
    {filter:JSON.stringify({_id:id})});showAlert('Deleted','success');loadDocs();}
  catch(e){showAlert('Del: '+e.message,'error');}}
async function insertDoc(){
  const db=document.getElementById('docDbSelect').value;const col=document.getElementById('docColSelect').value;
  const d=prompt('JSON:','{"key":"value"}');if(!d)return;
  try{await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/insert',{document:d});
    showAlert('Inserted','success');loadDocs();}
  catch(e){showAlert('Ins: '+e.message,'error');}}

function render_agg(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🔗</span>Aggregation Pipeline</div>' +
    '<div class="row"><select class="select grow" id="aggDb"></select>' +
    '<select class="select grow" id="aggCol"></select>' +
    '<button class="btn primary" onclick="runAgg()">▶ Run</button>' +
    '<button class="btn ghost" onclick="loadAggTemplate()">📋 Template</button></div>' +
    '<textarea class="textarea" id="aggPipeline" style="height:220px;margin-top:10px;"></textarea>' +
    '<div class="code" id="aggOut" style="margin-top:12px;max-height:500px;"></div></div>');
  loadDbsForSelect('aggDb', function(){loadColsForSelect('aggDb','aggCol');});
}
function loadAggTemplate(){
  document.getElementById('aggPipeline').value = JSON.stringify([
    {"$match":{}},{"$group":{"_id":"$status","count":{"$sum":1}}},{"$sort":{"count":-1}},{"$limit":10}
  ], null, 2);
}
async function runAgg(){
  const db=document.getElementById('aggDb').value;const col=document.getElementById('aggCol').value;
  const p=document.getElementById('aggPipeline').value;if(!db||!col||!p)return;
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/aggregate',{pipeline:p});
    setTxt('aggOut', JSON.stringify(j,null,2));}
  catch(e){setTxt('aggOut','Error: '+e.message);}
}

function render_gridfs(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📦</span>GridFS Buckets</div>' +
    '<div class="row"><select class="select grow" id="gfsDb"></select>' +
    '<input class="input grow" id="gfsBucket" placeholder="bucket" value="fs">' +
    '<button class="btn primary" onclick="listBuckets()">📂 Buckets</button>' +
    '<button class="btn" onclick="listFiles()">📄 Files</button></div></div>' +
    '<div id="gfsContent"></div>');
  loadDbsForSelect('gfsDb');
}
async function listBuckets(){
  const db=document.getElementById('gfsDb').value;
  try{const j=await api('/api/user/gridfs/buckets?db='+encodeURIComponent(db));
    setEl('gfsContent','<div class="card"><div class="card-title">Buckets in '+esc(db)+'</div>' +
      '<div class="table-wrap"><table><thead><tr><th>Bucket</th><th>Files</th><th></th></tr></thead><tbody>' +
      (j.buckets.map(function(b){return '<tr><td>'+esc(b.name)+'</td><td>'+b.files+'</td>' +
        '<td><button class="btn ghost sm" onclick="document.getElementById(\'gfsBucket\').value=\''+esc(b.name)+'\';listFiles()">View</button></td></tr>';}).join('')
        || '<tr><td colspan="3">'+empty('📦','No buckets')+'</td></tr>') + '</tbody></table></div></div>');}
  catch(e){showAlert('Buckets: '+e.message,'error');}
}
async function listFiles(){
  const db=document.getElementById('gfsDb').value;const bucket=document.getElementById('gfsBucket').value;
  try{const j=await api('/api/user/gridfs/'+encodeURIComponent(bucket)+'/files?db='+encodeURIComponent(db));
    setEl('gfsContent','<div class="card">' +
      '<div class="card-title">Upload to '+esc(bucket)+'</div>' +
      '<div class="row"><input class="input grow" id="gfsFilename" placeholder="filename.txt">' +
      '<button class="btn primary" onclick="uploadGfs()">⬆ Upload text</button></div></div>' +
      '<div class="card"><div class="card-title">Files ('+j.files.length+')</div>' +
      '<div class="table-wrap"><table><thead><tr><th>ID</th><th>Filename</th><th>Size</th><th>Uploaded</th><th>Actions</th></tr></thead><tbody>' +
      (j.files.map(function(f){
        const fid=esc(f._id);const fn=esc(f.filename||'file');
        return '<tr><td class="mono">'+esc((f._id||'').slice(-8))+'</td>' +
        '<td>'+fn+'</td><td>'+fmt(f.length||0)+'</td>' +
        '<td class="muted">'+esc((f.uploadDate||'').slice(0,19))+'</td>' +
        '<td><div class="row" style="margin:0;flex-wrap:wrap;gap:5px;">' +
          '<button class="btn green sm" onclick="dlGfs(\''+fid+'\')">⬇ Download</button>' +
          '<button class="btn danger sm" onclick="deleteGfs(\''+fid+'\')">🗑</button>' +
        '</div></td></tr>';}).join('') ||
        '<tr><td colspan="5">'+empty('📦','No files')+'</td></tr>') + '</tbody></table></div></div>');}
  catch(e){showAlert('Files: '+e.message,'error');}
}
async function uploadGfs(){
  const db=document.getElementById('gfsDb').value;const bucket=document.getElementById('gfsBucket').value;
  const filename=document.getElementById('gfsFilename').value.trim();if(!filename)return;
  const content=prompt('File content (text):','hello world');if(content===null)return;
  try{const j=await apiBody('/api/user/gridfs/'+encodeURIComponent(bucket)+'/upload',{db:db,filename:filename,content:content});
    showAlert('Uploaded '+j.size+' bytes','success');listFiles();}
  catch(e){showAlert('Upload: '+e.message,'error');}
}
async function deleteGfs(fid){
  const db=document.getElementById('gfsDb').value;const bucket=document.getElementById('gfsBucket').value;
  if(!confirm('Delete file?'))return;
  try{await apiBody('/api/user/gridfs/'+encodeURIComponent(bucket)+'/delete',{db:db,file_id:fid});
    showAlert('Deleted','success');listFiles();}
  catch(e){showAlert('Del: '+e.message,'error');}
}

window._termHistory = []; window._termIdx = -1;
function render_terminal(){
  setContent('<div class="card"><div class="card-title"><span class="ico">💻</span>MongoDB Shell' +
    '<span class="pill" style="margin-left:auto;">↑↓ history</span></div>' +
    '<div class="hint">Try: <code>show dbs</code> · <code>use mydb</code> · <code>db.users.find({})</code> · <code>{"ping":1}</code></div>' +
    '<div class="code" id="termLog" style="height:380px;"></div>' +
    '<div class="row" style="margin-top:12px;">' +
    '<span class="mono" style="color:#00ED64;font-weight:800;">›</span>' +
    '<input class="input grow mono" id="termInput" placeholder="show dbs" onkeydown="termKey(event)">' +
    '<button class="btn primary" onclick="runTerm()">Run</button></div></div>');
}
function termKey(e){
  const inp=document.getElementById('termInput');
  if(e.key==='Enter'){runTerm();return;}
  if(e.key==='ArrowUp'){e.preventDefault();if(!window._termHistory.length)return;
    if(window._termIdx===-1)window._termIdx=window._termHistory.length;
    window._termIdx=Math.max(0,window._termIdx-1);inp.value=window._termHistory[window._termIdx]||'';}
  if(e.key==='ArrowDown'){e.preventDefault();if(window._termIdx===-1)return;
    window._termIdx=Math.min(window._termHistory.length,window._termIdx+1);
    if(window._termIdx>=window._termHistory.length){window._termIdx=-1;inp.value='';}
    else inp.value=window._termHistory[window._termIdx];}
}
async function runTerm(){
  const inp=document.getElementById('termInput');const cmd=inp.value.trim();if(!cmd)return;
  window._termHistory.push(cmd);window._termIdx=-1;
  const log=document.getElementById('termLog');
  log.textContent+='\n› '+cmd;inp.value='';
  try{const j=await apiBody('/api/user/terminal',{command:cmd,db:termDb});
    if(j.db)termDb=j.db;log.textContent+='\n'+JSON.stringify(j.output,null,2);}
  catch(e){log.textContent+='\n[error] '+e.message;}
  log.scrollTop=log.scrollHeight;
}

function render_users_roles(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🔐</span>Database Users</div>' +
    '<div class="row"><select class="select grow" id="urDb"><option value="admin">admin</option></select>' +
    '<button class="btn primary" onclick="loadUsersList()">👥 Users</button>' +
    '<button class="btn" onclick="loadRolesList()">🎭 Roles</button>' +
    '<button class="btn" onclick="showCreateUser()">➕ User</button>' +
    '<button class="btn" onclick="showCreateRole()">✨ Role</button></div></div>' +
    '<div id="urContent"></div>');
  loadDbsForSelect('urDb');
}
async function loadUsersList(){const db=document.getElementById('urDb').value;
  try{const j=await api('/api/user/users?db='+encodeURIComponent(db));
    setEl('urContent','<div class="card"><div class="card-title">Users in '+esc(db)+'</div>' +
      '<div class="table-wrap"><table><thead><tr><th>User</th><th>Roles</th><th>Actions</th></tr></thead><tbody>' +
      ((j.users||[]).map(function(u){
        return '<tr><td>'+esc(u.user)+'</td>' +
        '<td>'+((u.roles||[]).map(function(r){return '<span class="pill blue">'+esc(r.role)+'@'+esc(r.db||'')+'</span>';}).join(' '))+'</td>' +
        '<td><div class="row" style="margin:0;flex-wrap:wrap;gap:5px;">' +
        '<button class="btn ghost sm" onclick="grantRole(\''+esc(u.user)+'\')">➕</button>' +
        '<button class="btn ghost sm" onclick="revokeRole(\''+esc(u.user)+'\')">➖</button>' +
        '<button class="btn danger sm" onclick="dropUser(\''+esc(u.user)+'\')">🗑</button>' +
        '</div></td></tr>';}).join('')
        || '<tr><td colspan="3">'+empty('👥','No users')+'</td></tr>') + '</tbody></table></div></div>');}
  catch(e){showAlert(e.message,'error');}}
async function loadRolesList(){const db=document.getElementById('urDb').value;
  try{const j=await api('/api/user/roles?db='+encodeURIComponent(db));
    setEl('urContent','<div class="card"><div class="card-title">Roles in '+esc(db)+'</div>' +
      '<div class="table-wrap"><table><thead><tr><th>Role</th><th>Privileges</th><th>Inherits</th><th></th></tr></thead><tbody>' +
      ((j.roles||[]).map(function(r){
        return '<tr><td>'+esc(r.role)+'</td><td>'+((r.privileges||[]).length)+'</td>' +
        '<td>'+((r.roles||[]).length)+'</td>' +
        '<td>'+(r.isBuiltin?'<span class="pill green">builtin</span>':'<button class="btn danger sm" onclick="dropRole(\''+esc(r.role)+'\')">🗑</button>')+'</td></tr>';}).join('')
        || '<tr><td colspan="4">'+empty('🎭','No roles')+'</td></tr>') + '</tbody></table></div></div>');}
  catch(e){showAlert(e.message,'error');}}
function showCreateUser(){const db=document.getElementById('urDb').value;
  const name=prompt('Username:');if(!name)return;
  const pwd=prompt('Password:');if(!pwd)return;
  const roles=prompt('Roles JSON:','[{"role":"readWrite","db":"test"}]');if(!roles)return;
  apiBody('/api/user/user/create',{db:db,user:name,pwd:pwd,roles:JSON.parse(roles)})
    .then(function(){showAlert('User created','success');loadUsersList();})
    .catch(function(e){showAlert(e.message,'error');});}
function grantRole(user){const db=document.getElementById('urDb').value;
  const roles=prompt('Grant:','[{"role":"readWrite","db":"test"}]');if(!roles)return;
  apiBody('/api/user/user/grant',{db:db,user:user,roles:JSON.parse(roles)})
    .then(function(){showAlert('Granted','success');loadUsersList();})
    .catch(function(e){showAlert(e.message,'error');});}
function revokeRole(user){const db=document.getElementById('urDb').value;
  const roles=prompt('Revoke:','[{"role":"readWrite","db":"test"}]');if(!roles)return;
  apiBody('/api/user/user/revoke',{db:db,user:user,roles:JSON.parse(roles)})
    .then(function(){showAlert('Revoked','success');loadUsersList();})
    .catch(function(e){showAlert(e.message,'error');});}
function dropUser(user){const db=document.getElementById('urDb').value;
  if(!confirm('Drop user '+user+'?'))return;
  apiBody('/api/user/user/drop',{db:db,user:user})
    .then(function(){showAlert('Dropped','success');loadUsersList();})
    .catch(function(e){showAlert(e.message,'error');});}
function showCreateRole(){const db=document.getElementById('urDb').value;
  const name=prompt('Role name:');if(!name)return;
  const privs=prompt('Privileges:','[{"resource":{"db":"test","collection":""},"actions":["find","insert"]}]');if(!privs)return;
  const roles=prompt('Inherited roles:','[]')||'[]';
  apiBody('/api/user/role/create',{db:db,role:name,privileges:JSON.parse(privs),roles:JSON.parse(roles)})
    .then(function(){showAlert('Role created','success');loadRolesList();})
    .catch(function(e){showAlert(e.message,'error');});}
function dropRole(role){const db=document.getElementById('urDb').value;
  if(!confirm('Drop role '+role+'?'))return;
  apiBody('/api/user/role/drop',{db:db,role:role})
    .then(function(){showAlert('Dropped','success');loadRolesList();})
    .catch(function(e){showAlert(e.message,'error');});}

function render_sessions(){
  setContent('<div class="card"><div class="card-title"><span class="ico">👻</span>Live Sessions' +
    '<button class="btn ghost sm" style="margin-left:auto;" onclick="loadSessions()">↻</button>' +
    '<button class="btn danger sm" onclick="killAllSessions()">💀 All</button></div>' +
    '<div class="row"><input class="input grow" id="sessUser" placeholder="username">' +
    '<button class="btn danger" onclick="killByUser()">Kill by User</button></div>' +
    '<div class="table-wrap"><table><thead><tr><th>User</th><th>Session ID</th><th>Last Use</th></tr></thead>' +
    '<tbody id="sessRows"><tr><td colspan="3">'+empty('👻','Loading...')+'</td></tr></tbody></table></div></div>');
  loadSessions();
}
async function loadSessions(){
  try{const j=await api('/api/user/sessions');
    setEl('sessRows',((j.sessions||[]).map(function(s){
      return '<tr><td>'+esc(s.user||'')+'</td>' +
      '<td class="mono">'+esc((s._id||'').slice(-12))+'</td>' +
      '<td class="muted">'+esc((s.lastUse||'').slice(0,19))+'</td></tr>';}).join('')
      || '<tr><td colspan="3">'+empty('👻','No sessions')+'</td></tr>'));}
  catch(e){showAlert(e.message,'error');}
}
async function killAllSessions(){if(!confirm('Kill ALL?'))return;
  try{await apiBody('/api/user/sessions/kill',{all:true});showAlert('Killed','success');loadSessions();}
  catch(e){showAlert(e.message,'error');}}
async function killByUser(){const u=document.getElementById('sessUser').value.trim();if(!u)return;
  try{await apiBody('/api/user/sessions/kill',{user:u});showAlert('Killed '+u,'success');loadSessions();}
  catch(e){showAlert(e.message,'error');}}

function render_monitor(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📡</span>Live Metrics' +
    '<button class="btn ghost sm" style="margin-left:auto;" onclick="loadMonitor()">↻</button></div>' +
    '<div class="grid cols-3" id="monitorStats"></div>' +
    '<div class="grid cols-2" style="margin-top:16px;">' +
    '<div class="card" style="margin:0;"><div class="card-title">Ops / sec</div>' +
    '<canvas id="chartOps" width="400" height="140" style="width:100%;height:140px;"></canvas></div>' +
    '<div class="card" style="margin:0;"><div class="card-title">Memory (MB)</div>' +
    '<canvas id="chartMem" width="400" height="140" style="width:100%;height:140px;"></canvas></div>' +
    '</div>' +
    '<div class="card" style="margin-top:14px;"><div class="card-title">Raw</div>' +
    '<div class="code" id="monitorRaw" style="max-height:280px;"></div></div></div>');
  window._monHistory = {ops:[], mem:[]};
  loadMonitor();
  if(window._monTimer) clearInterval(window._monTimer);
  window._monTimer = setInterval(loadMonitor, 3000);
}
async function loadMonitor(){
  try{const j = await api('/api/user/monitor');
    setEl('monitorStats',
      '<div class="stat"><span class="num">'+((j.connections||{}).current||0)+'</span><span class="lbl">Conns</span></div>' +
      '<div class="stat blue"><span class="num">'+((j.mem||{}).resident||0)+'</span><span class="lbl">Mem MB</span></div>' +
      '<div class="stat amber"><span class="num">'+(j.uptime||0)+'</span><span class="lbl">Uptime s</span></div>' +
      '<div class="stat purple"><span class="num">'+fmt((j.network||{}).bytesIn||0)+'</span><span class="lbl">In</span></div>' +
      '<div class="stat purple"><span class="num">'+fmt((j.network||{}).bytesOut||0)+'</span><span class="lbl">Out</span></div>' +
      '<div class="stat blue"><span class="num">'+((j.opcounters||{}).query||0)+'</span><span class="lbl">Queries</span></div>');
    setTxt('monitorRaw', JSON.stringify(j,null,2));
    const h = window._monHistory;
    if(h){const oc = j.opcounters||{};
      const totalOps = (oc.query||0)+(oc.insert||0)+(oc.update||0)+(oc.delete||0)+(oc.command||0);
      h.ops.push(totalOps); h.mem.push((j.mem||{}).resident||0);
      if(h.ops.length > 40){h.ops.shift(); h.mem.shift();}
      drawLine('chartOps', h.ops, '#00ED64'); drawLine('chartMem', h.mem, '#0498EC');}
  }catch(e){showAlert(e.message,'error');}
}
function drawLine(canvasId, data, color){
  const c=document.getElementById(canvasId);if(!c)return;
  const ctx=c.getContext('2d');const W=c.width, H=c.height;
  ctx.clearRect(0,0,W,H);if(data.length<2)return;
  const max=Math.max.apply(null,data.concat([1]));
  const min=Math.min.apply(null,data.concat([0]));
  const range=max-min||1;const stepX=W/(data.length-1);
  ctx.strokeStyle='rgba(44,61,72,.4)';ctx.lineWidth=1;
  for(let i=0;i<=4;i++){const y=i*(H/4);ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
  ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2;
  ctx.shadowColor=color;ctx.shadowBlur=8;
  data.forEach(function(v,i){const x=i*stepX;const y=H-((v-min)/range)*(H-20)-10;
    if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);});
  ctx.stroke();ctx.lineTo(W,H);ctx.lineTo(0,H);ctx.closePath();
  if(color.startsWith('#')){const r=parseInt(color.slice(1,3),16),g=parseInt(color.slice(3,5),16),b=parseInt(color.slice(5,7),16);
    ctx.fillStyle='rgba('+r+','+g+','+b+',0.10)';}
  ctx.fill();ctx.shadowBlur=0;
}

function render_metrics(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📈</span>Server Metrics' +
    '<button class="btn ghost sm" style="margin-left:auto;" onclick="loadMetrics()">↻</button></div>' +
    '<div id="metricsGrid"></div>' +
    '<div class="code" id="metricsRaw" style="margin-top:12px;max-height:400px;"></div></div>');
  loadMetrics();
}
async function loadMetrics(){
  try{const j=await api('/api/user/server/metrics');const oc=j.opcounters||{};
    setEl('metricsGrid','<div class="metric-mini">' +
      '<div class="m"><div class="v">'+(oc.query||0)+'</div><div class="k">Queries</div></div>' +
      '<div class="m"><div class="v">'+(oc.insert||0)+'</div><div class="k">Inserts</div></div>' +
      '<div class="m"><div class="v">'+(oc.update||0)+'</div><div class="k">Updates</div></div>' +
      '<div class="m"><div class="v">'+(oc.delete||0)+'</div><div class="k">Deletes</div></div>' +
      '<div class="m"><div class="v">'+(oc.command||0)+'</div><div class="k">Commands</div></div>' +
      '<div class="m"><div class="v">'+(((j.opcountersRepl||{}).query)||0)+'</div><div class="k">Repl Q</div></div>' +
      '</div>');
    setTxt('metricsRaw',JSON.stringify(j,null,2));}
  catch(e){showAlert(e.message,'error');}
}

function render_profiler(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🔬</span>Running Operations' +
    '<button class="btn ghost sm" style="margin-left:auto;" onclick="loadOps()">↻</button></div>' +
    '<div class="row"><select class="select grow" id="profileLevel" onchange="setProfileLevel()">' +
    '<option value="0">Off</option><option value="1">Slow</option><option value="2">All</option></select>' +
    '<button class="btn" onclick="loadSlow()">🐢 Slow</button></div>' +
    '<div class="table-wrap"><table><thead><tr><th>OpID</th><th>Op</th><th>NS</th><th>Secs</th><th></th></tr></thead>' +
    '<tbody id="opsRows"><tr><td colspan="5">'+empty('🔬','Refresh')+'</td></tr></tbody></table></div></div>' +
    '<div class="card"><div class="card-title">Slow queries</div><div class="code" id="slowBox"></div></div>');
  loadOps();
}
async function loadOps(){
  try{const j=await api('/api/user/profiler/current');
    setEl('opsRows',((j.ops||[]).map(function(o){
      return '<tr><td class="mono">'+(o.opid||'')+'</td><td>'+esc(o.op||'')+'</td>' +
      '<td class="mono">'+esc(o.ns||'')+'</td><td>'+(o.secs_running||0)+'</td>' +
      '<td><button class="btn danger sm" onclick="killOp('+(o.opid||0)+')">Kill</button></td></tr>';}).join('')
      || '<tr><td colspan="5">'+empty('✨','No active')+'</td></tr>'));}
  catch(e){showAlert(e.message,'error');}
}
async function killOp(opid){if(!confirm('Kill op '+opid+'?'))return;
  try{await apiBody('/api/user/profiler/kill',{opid:opid});showAlert('Killed','success');loadOps();}
  catch(e){showAlert(e.message,'error');}}
async function setProfileLevel(){try{await apiBody('/api/user/profiler/level',{level:parseInt(document.getElementById('profileLevel').value)});
  showAlert('Level set','success');}catch(e){showAlert(e.message,'error');}}
async function loadSlow(){try{const j=await api('/api/user/profiler/slow');
  setTxt('slowBox',JSON.stringify(j.slow||[],null,2));}
  catch(e){showAlert(e.message,'error');}}

function render_explain(){
  setContent('<div class="card"><div class="card-title"><span class="ico">⚡</span>Explain Query</div>' +
    '<div class="row"><select class="select grow" id="expDb"></select>' +
    '<select class="select grow" id="expCol"></select>' +
    '<select class="select grow" id="expVerb">' +
    '<option value="executionStats">executionStats</option>' +
    '<option value="queryPlanner">queryPlanner</option>' +
    '<option value="allPlansExecution">allPlansExecution</option></select></div>' +
    '<input class="input" id="expFilter" placeholder="filter JSON" value="{}" style="margin-bottom:10px;">' +
    '<button class="btn primary" onclick="runExplain()">▶ Analyze</button>' +
    '<div class="code" id="expOut" style="margin-top:12px;max-height:500px;"></div></div>');
  loadDbsForSelect('expDb', function(){loadColsForSelect('expDb','expCol');});
}
async function runExplain(){
  const db=document.getElementById('expDb').value;const col=document.getElementById('expCol').value;
  const filter=document.getElementById('expFilter').value||'{}';
  const verbosity=document.getElementById('expVerb').value;
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/explain',{filter:filter,verbosity:verbosity});
    setTxt('expOut',JSON.stringify(j.explain,null,2));}
  catch(e){setTxt('expOut','Error: '+e.message);}
}

function render_changes(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🔥</span>Change Streams</div>' +
    '<div class="row"><select class="select grow" id="chScope">' +
    '<option value="collection">Collection</option><option value="database">Database</option></select>' +
    '<select class="select grow" id="chDb"></select>' +
    '<select class="select grow" id="chCol"></select>' +
    '<input class="input" id="chDur" type="number" value="10" style="max-width:100px;"><span class="muted">sec</span>' +
    '<button class="btn primary" onclick="watchChanges()">👁 Watch</button></div>' +
    '<div class="code" id="chOut" style="max-height:400px;"></div></div>');
  loadDbsForSelect('chDb', function(){loadColsForSelect('chDb','chCol');});
}
async function watchChanges(){
  const scope=document.getElementById('chScope').value;const db=document.getElementById('chDb').value;
  const col=document.getElementById('chCol').value;const dur=parseInt(document.getElementById('chDur').value)||10;
  const out=document.getElementById('chOut'); if(out) out.textContent='Watching '+dur+'s...';
  try{const url=scope==='database'?'/api/user/db/'+encodeURIComponent(db)+'/changes'
      :'/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/changes';
    const j=await apiBody(url,{duration:dur});setTxt('chOut',JSON.stringify(j.events,null,2));}
  catch(e){setTxt('chOut','Error: '+e.message);}
}

function render_repl(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🌐</span>Replication' +
    '<button class="btn ghost sm" style="margin-left:auto;" onclick="loadRepl()">↻</button></div>' +
    '<div id="replOut"></div></div>');
  loadRepl();
}
async function loadRepl(){
  try{const rs=await api('/api/user/repl/status');
    if(!rs.replicaSet){setEl('replOut','<div class="hint warn">Not a replica set: '+esc(rs.message||'')+'</div>');return;}
    const members=(rs.status.members||[]).map(function(m){return '<div class="m"><div class="v">'+esc(m.stateStr||'')+'</div><div class="k">'+esc(m.name||'')+'</div></div>';}).join('');
    setEl('replOut','<div class="metric-mini">'+members+'</div>' +
      '<div class="code" style="margin-top:12px;max-height:400px;">'+esc(JSON.stringify(rs.status,null,2).slice(0,5000))+'</div>');}
  catch(e){showAlert(e.message,'error');}
}

function render_server(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🛰</span>Server Info</div>' +
    '<div class="tabs">' +
    '<div class="tab active" onclick="loadServer(\'buildinfo\',this)">buildInfo</div>' +
    '<div class="tab" onclick="loadServer(\'hostinfo\',this)">hostInfo</div>' +
    '<div class="tab" onclick="loadServer(\'connstatus\',this)">connectionStatus</div>' +
    '<div class="tab" onclick="loadServer(\'cmdline\',this)">getCmdLineOpts</div>' +
    '</div>' +
    '<div class="code" id="serverOut" style="max-height:500px;"></div></div>');
  loadServer('buildinfo');
}
async function loadServer(which, el){
  if(el){document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');});el.classList.add('active');}
  try{const j=await api('/api/user/server/'+which);
    setTxt('serverOut',JSON.stringify(j.info,null,2));}
  catch(e){showAlert(e.message,'error');}
}

function render_top(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📊</span>Top Operations' +
    '<button class="btn ghost sm" style="margin-left:auto;" onclick="loadTop()">↻</button></div>' +
    '<div class="code" id="topOut" style="max-height:500px;"></div></div>');
  loadTop();
}
async function loadTop(){try{const j=await api('/api/user/server/top');
  setTxt('topOut',JSON.stringify(j.info,null,2));}
  catch(e){showAlert(e.message,'error');}}

function render_logs(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📋</span>Logs & Cluster</div>' +
    '<div class="row"><button class="btn primary" onclick="loadLogs()">↻ Server Log</button>' +
    '<button class="btn" onclick="loadCluster()">🔧 Cluster</button>' +
    '<button class="btn danger" onclick="rotateLogs()">🔄 Rotate</button></div>' +
    '<div class="code" id="logsOut" style="max-height:500px;"></div></div>');
}
async function loadLogs(){try{const j=await api('/api/user/logs');
  setTxt('logsOut',(j.log||[]).join('\n'));}
  catch(e){showAlert(e.message,'error');}}
async function loadCluster(){try{const j=await api('/api/user/cluster');
  setTxt('logsOut',JSON.stringify(j,null,2));}
  catch(e){showAlert(e.message,'error');}}
async function rotateLogs(){if(!confirm('Rotate logs?'))return;
  try{await apiBody('/api/user/logrotate',{});showAlert('Rotated','success');}
  catch(e){showAlert(e.message,'error');}}

function render_dbstats(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📊</span>Database Stats</div>' +
    '<div class="row"><select class="select grow" id="dsDb"></select>' +
    '<button class="btn primary" onclick="loadDs()">▶ Load</button></div>' +
    '<div class="code" id="dsOut" style="max-height:500px;"></div></div>');
  loadDbsForSelect('dsDb');
}
async function loadDs(){const db=document.getElementById('dsDb').value;
  try{const j=await api('/api/user/db/'+encodeURIComponent(db)+'/stats');
    setTxt('dsOut',JSON.stringify(j.stats,null,2));}
  catch(e){showAlert(e.message,'error');}}
function render_colstats(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📈</span>Collection Stats</div>' +
    '<div class="row"><select class="select grow" id="csDb"></select>' +
    '<select class="select grow" id="csCol"></select>' +
    '<button class="btn primary" onclick="loadCs()">▶ Load</button></div>' +
    '<div class="code" id="csOut" style="max-height:500px;"></div></div>');
  loadDbsForSelect('csDb', function(){loadColsForSelect('csDb','csCol');});
}
async function loadCs(){const db=document.getElementById('csDb').value;const col=document.getElementById('csCol').value;
  try{const j=await api('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/stats');
    setTxt('csOut',JSON.stringify(j.stats,null,2));}
  catch(e){showAlert(e.message,'error');}}

function render_indexes(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🔖</span>Indexes</div>' +
    '<div class="row"><select class="select grow" id="ixDb"></select>' +
    '<select class="select grow" id="ixCol"></select></div>' +
    '<div class="row"><button class="btn primary" onclick="loadIndexes()">📋 List</button>' +
    '<button class="btn" onclick="loadIxStats()">📊 Usage</button>' +
    '<button class="btn" onclick="showCreateIndex()">➕ Create</button></div>' +
    '<div id="ixContent"></div></div>');
  loadDbsForSelect('ixDb', function(){loadColsForSelect('ixDb','ixCol');});
}
async function loadIndexes(){const db=document.getElementById('ixDb').value;const col=document.getElementById('ixCol').value;
  try{const j=await api('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/indexes');
    setEl('ixContent','<div class="table-wrap" style="margin-top:12px;">' +
      '<table><thead><tr><th>Name</th><th>Key</th><th>Unique</th><th>TTL</th><th></th></tr></thead><tbody>' +
      (j.indexes.map(function(i){return '<tr><td>'+esc(i.name)+'</td>' +
        '<td class="mono">'+esc(JSON.stringify(i.key))+'</td>' +
        '<td>'+(i.unique?'<span class="pill green">YES</span>':'—')+'</td>' +
        '<td>'+(i.expireAfterSeconds||'—')+'</td>' +
        '<td>'+(i.name==='_id_'?'':'<button class="btn danger sm" onclick="dropIx(\''+esc(i.name)+'\')">🗑</button>')+'</td></tr>';}).join('')) +
      '</tbody></table></div>');}
  catch(e){showAlert(e.message,'error');}}
async function loadIxStats(){const db=document.getElementById('ixDb').value;const col=document.getElementById('ixCol').value;
  try{const j=await api('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/index/stats');
    setEl('ixContent','<div class="table-wrap" style="margin-top:12px;">' +
      '<table><thead><tr><th>Index</th><th>Accesses</th><th>Since</th></tr></thead><tbody>' +
      (j.stats.map(function(s){return '<tr><td>'+esc(s.name)+'</td>' +
        '<td>'+(((s.accesses||{}).ops)||0)+'</td>' +
        '<td class="muted">'+esc((((s.accesses||{}).since)||'').slice(0,19))+'</td></tr>';}).join('')) +
      '</tbody></table></div>');}
  catch(e){showAlert(e.message,'error');}}
function showCreateIndex(){const keys=prompt('Keys:','{"field":1}');if(!keys)return;
  const opts=prompt('Options:','{}')||'{}';
  const db=document.getElementById('ixDb').value;const col=document.getElementById('ixCol').value;
  apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/index/create',{keys:keys,options:opts})
    .then(function(){showAlert('Created','success');loadIndexes();})
    .catch(function(e){showAlert(e.message,'error');});}
async function dropIx(name){const db=document.getElementById('ixDb').value;const col=document.getElementById('ixCol').value;
  if(!confirm('Drop index '+name+'?'))return;
  try{await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/index/drop',{name:name});
    showAlert('Dropped','success');loadIndexes();}
  catch(e){showAlert(e.message,'error');}}

function render_text(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🔎</span>Full-Text Search</div>' +
    '<div class="hint warn">Needs a text index. Create one via Indexes panel.</div>' +
    '<div class="row"><select class="select grow" id="txtDb"></select>' +
    '<select class="select grow" id="txtCol"></select>' +
    '<input class="input grow" id="txtQuery" placeholder="search words">' +
    '<button class="btn primary" onclick="runText()">🔍</button></div>' +
    '<div class="code" id="txtOut" style="max-height:500px;"></div></div>');
  loadDbsForSelect('txtDb', function(){loadColsForSelect('txtDb','txtCol');});
}
async function runText(){const db=document.getElementById('txtDb').value;const col=document.getElementById('txtCol').value;
  const query=document.getElementById('txtQuery').value.trim();if(!query)return;
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/text',{query:query});
    setTxt('txtOut',JSON.stringify(j,null,2));}
  catch(e){setTxt('txtOut','Error: '+e.message);}}
function render_distinct(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🎯</span>Distinct Values</div>' +
    '<div class="row"><select class="select grow" id="dDb"></select>' +
    '<select class="select grow" id="dCol"></select>' +
    '<input class="input" id="dKey" placeholder="field" value="status">' +
    '<input class="input grow" id="dFilter" placeholder="filter" value="{}">' +
    '<button class="btn primary" onclick="runDistinct()">▶</button></div>' +
    '<div class="code" id="dOut" style="max-height:500px;"></div></div>');
  loadDbsForSelect('dDb', function(){loadColsForSelect('dDb','dCol');});
}
async function runDistinct(){const db=document.getElementById('dDb').value;const col=document.getElementById('dCol').value;
  const key=document.getElementById('dKey').value.trim();const filter=document.getElementById('dFilter').value||'{}';
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/distinct',{key:key,filter:filter});
    setTxt('dOut',JSON.stringify(j,null,2));}
  catch(e){setTxt('dOut','Error: '+e.message);}}

function render_fam(){
  setContent('<div class="card"><div class="card-title"><span class="ico">✏️</span>findAndModify</div>' +
    '<div class="row"><select class="select grow" id="famDb"></select>' +
    '<select class="select grow" id="famCol"></select></div>' +
    '<div class="grid cols-2">' +
    '<div class="field"><label>Query</label><textarea class="textarea" id="famQuery">{"_id":"..."}</textarea></div>' +
    '<div class="field"><label>Update</label><textarea class="textarea" id="famUpdate">{"$set":{"field":"value"}}</textarea></div></div>' +
    '<div class="row"><label style="color:#C1C7C6;font-size:12px;display:flex;align-items:center;gap:6px;"><input type="checkbox" id="famNew"> New</label>' +
    '<label style="color:#C1C7C6;font-size:12px;display:flex;align-items:center;gap:6px;"><input type="checkbox" id="famUpsert"> Upsert</label>' +
    '<label style="color:#C1C7C6;font-size:12px;display:flex;align-items:center;gap:6px;"><input type="checkbox" id="famRemove"> Remove</label>' +
    '<button class="btn primary" onclick="runFam()">▶ Execute</button></div>' +
    '<div class="code" id="famOut" style="max-height:400px;"></div></div>');
  loadDbsForSelect('famDb', function(){loadColsForSelect('famDb','famCol');});
}
async function runFam(){const db=document.getElementById('famDb').value;const col=document.getElementById('famCol').value;
  const query=document.getElementById('famQuery').value;const update=document.getElementById('famUpdate').value;
  const isNew=document.getElementById('famNew').checked;const upsert=document.getElementById('famUpsert').checked;
  const remove=document.getElementById('famRemove').checked;
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/findandmodify',
      {query:query,update:update,new:isNew,upsert:upsert,remove:remove});
    setTxt('famOut',JSON.stringify(j,null,2));}
  catch(e){setTxt('famOut','Error: '+e.message);}}
function render_bulk(){
  setContent('<div class="card"><div class="card-title"><span class="ico">⚙️</span>Bulk Write</div>' +
    '<div class="row"><select class="select grow" id="bulkDb"></select>' +
    '<select class="select grow" id="bulkCol"></select></div>' +
    '<div class="hint">Ops: <code>[{"type":"insertOne","document":{}}]</code></div>' +
    '<textarea class="textarea" id="bulkOps" style="height:200px;">[]</textarea>' +
    '<button class="btn primary" style="margin-top:10px;" onclick="runBulk()">▶ Execute</button>' +
    '<div class="code" id="bulkOut" style="margin-top:12px;"></div></div>');
  loadDbsForSelect('bulkDb', function(){loadColsForSelect('bulkDb','bulkCol');});
}
async function runBulk(){const db=document.getElementById('bulkDb').value;const col=document.getElementById('bulkCol').value;
  const ops=document.getElementById('bulkOps').value;
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/bulk',{operations:ops});
    setTxt('bulkOut',JSON.stringify(j,null,2));}
  catch(e){setTxt('bulkOut','Error: '+e.message);}}

function render_mask(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🎭</span>Anonymize PII</div>' +
    '<div class="row"><select class="select grow" id="maskDb"></select>' +
    '<select class="select grow" id="maskCol"></select>' +
    '<select class="select grow" id="maskStrategy">' +
    '<option value="redact">redact</option><option value="hash">hash</option>' +
    '<option value="random">random</option><option value="null">null</option>' +
    '<option value="fake_email">fake_email</option><option value="fake_phone">fake_phone</option>' +
    '<option value="shuffle">shuffle</option></select></div>' +
    '<div class="field"><label>Fields (comma separated)</label>' +
    '<input class="input" id="maskFields" placeholder="email, phone"></div>' +
    '<button class="btn primary" onclick="runMask()">Apply</button></div>');
  loadDbsForSelect('maskDb', function(){loadColsForSelect('maskDb','maskCol');});
}
async function runMask(){const db=document.getElementById('maskDb').value;const col=document.getElementById('maskCol').value;
  const fieldsStr=document.getElementById('maskFields').value.trim();const strat=document.getElementById('maskStrategy').value;
  if(!db||!col||!fieldsStr){showAlert('Fill all','error');return;}
  const fields=fieldsStr.split(',').map(function(f){return {path:f.trim(),strategy:strat};});
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/mask',{fields:fields});
    showAlert('Masked '+j.updated,'success');}
  catch(e){showAlert(e.message,'error');}}
function render_io(){
  setContent('<div class="card"><div class="card-title"><span class="ico">📦</span>Export</div>' +
    '<div class="row"><select class="select grow" id="ioDb"></select>' +
    '<select class="select grow" id="ioCol"></select></div>' +
    '<div class="row"><button class="btn green" onclick="doExport(\'json\')">⬇ JSON</button>' +
    '<button class="btn green" onclick="doExport(\'csv\')">⬇ CSV</button>' +
    '<button class="btn green" onclick="doExport(\'jsonl\')">⬇ JSONL</button>' +
    '<button class="btn primary" onclick="doExport(\'zip\')">⬇ ZIP</button></div></div>' +
    '<div class="card"><div class="card-title"><span class="ico">📥</span>Import JSON / JSONL</div>' +
    '<textarea class="textarea" id="importJson" style="height:180px;"></textarea>' +
    '<button class="btn primary" style="margin-top:10px;" onclick="doImport()">Import</button></div>' +
    '<div class="card"><div class="card-title">Output</div><div class="code" id="ioOut" style="max-height:400px;"></div></div>');
  loadDbsForSelect('ioDb', function(){loadColsForSelect('ioDb','ioCol');});
}
async function doExport(fmt){
  const db=document.getElementById('ioDb').value;const col=document.getElementById('ioCol').value;
  if(!db||!col)return;
  if(fmt==='zip'){dlCol(db,col,'zip');return;}
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/export',{format:fmt});
    const txt = fmt==='csv' ? j.csv : (fmt==='jsonl' ? j.jsonl : JSON.stringify(j.json,null,2));
    setTxt('ioOut', txt || '');}
  catch(e){showAlert(e.message,'error');}}
async function doImport(){const db=document.getElementById('ioDb').value;const col=document.getElementById('ioCol').value;
  const j=document.getElementById('importJson').value;if(!db||!col||!j)return;
  try{const r=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/import',{json:j});
    showAlert('Imported '+r.inserted,'success');}
  catch(e){showAlert(e.message,'error');}}
function render_backup(){
  setContent('<div class="card"><div class="card-title"><span class="ico">💾</span>mongodump</div>' +
    '<div class="hint warn">mongodump must be installed in container.</div>' +
    '<div class="row"><input class="input grow" id="backupDb" placeholder="db name (blank = all)">' +
    '<button class="btn primary" onclick="doBackup()">Run</button></div>' +
    '<div class="code" id="backupOut" style="margin-top:12px;max-height:400px;"></div></div>');
}
async function doBackup(){const db=document.getElementById('backupDb').value;
  setTxt('backupOut','Running...');
  try{const j=await apiBody('/api/user/backup',{db:db});setTxt('backupOut',JSON.stringify(j,null,2));}
  catch(e){setTxt('backupOut','Error: '+e.message);}}

function render_danger(){
  setContent('<div class="card"><div class="card-title"><span class="ico" style="color:#FF3B5C;">⚠️</span>Destructive</div>' +
    '<div class="hint danger">Cannot undo.</div>' +
    '<div class="row"><select class="select grow" id="dangerDb"></select>' +
    '<select class="select grow" id="dangerCol"></select></div>' +
    '<div class="row"><button class="btn danger" onclick="dropColl()">🔥 Drop Collection</button>' +
    '<button class="btn danger" onclick="dropDbAct()">🔥 Drop Database</button>' +
    '<button class="btn danger" onclick="dropIxs()">🔥 Drop All Indexes</button></div></div>' +
    '<div class="card"><div class="card-title"><span class="ico">⌨️</span>Raw Command</div>' +
    '<select class="select" id="rawDb" style="margin-bottom:10px;"><option value="admin">admin</option></select>' +
    '<textarea class="textarea" id="rawCmd" placeholder=\'{"ping":1}\'></textarea>' +
    '<button class="btn danger" style="margin-top:10px;" onclick="runRaw()">Execute</button>' +
    '<div class="code" id="dangerOut" style="margin-top:12px;"></div></div>');
  loadDbsForSelect('dangerDb', function(){loadColsForSelect('dangerDb','dangerCol');});
  loadDbsForSelect('rawDb');
}
async function dropColl(){const db=document.getElementById('dangerDb').value;const col=document.getElementById('dangerCol').value;
  if(!confirm('Drop '+db+'.'+col+'?'))return;
  try{await apiBody('/api/user/db/'+encodeURIComponent(db)+'/collection/drop',{name:col});showAlert('Dropped','success');}
  catch(e){showAlert(e.message,'error');}}
async function dropDbAct(){const db=document.getElementById('dangerDb').value;
  if(!confirm('Drop DB '+db+'?'))return;
  try{await apiBody('/api/user/database/drop',{name:db});showAlert('Dropped','success');}
  catch(e){showAlert(e.message,'error');}}
async function dropIxs(){const db=document.getElementById('dangerDb').value;const col=document.getElementById('dangerCol').value;
  if(!confirm('Drop all indexes?'))return;
  try{await apiBody('/api/user/db/'+encodeURIComponent(db)+'/drop-all-indexes',{collection:col});showAlert('Dropped','success');}
  catch(e){showAlert(e.message,'error');}}
async function runRaw(){const cmd=document.getElementById('rawCmd').value;const db=document.getElementById('rawDb').value||'admin';
  try{const j=await apiBody('/api/user/raw',{command:cmd,db:db});
    setTxt('dangerOut',JSON.stringify(j.result,null,2));}
  catch(e){setTxt('dangerOut','Error: '+e.message);}}
function render_advanced_cmd(){
  setContent('<div class="card"><div class="card-title"><span class="ico">💥</span>Advanced Commands</div>' +
    '<div class="row"><select class="select grow" id="advDb"></select>' +
    '<select class="select grow" id="advCol"></select></div>' +
    '<div class="row"><button class="btn primary" onclick="advValidate()">✔ Validate</button>' +
    '<button class="btn" onclick="advReindex()">🔁 ReIndex</button>' +
    '<button class="btn danger" onclick="advCompact()">🗜 Compact</button></div>' +
    '<div class="code" id="advOut" style="max-height:500px;"></div></div>');
  loadDbsForSelect('advDb', function(){loadColsForSelect('advDb','advCol');});
}
async function advValidate(){const db=document.getElementById('advDb').value;const col=document.getElementById('advCol').value;
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/validate',{full:true});
    setTxt('advOut',JSON.stringify(j.result,null,2));}
  catch(e){setTxt('advOut','Error: '+e.message);}}
async function advReindex(){const db=document.getElementById('advDb').value;const col=document.getElementById('advCol').value;
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/reindex',{});
    setTxt('advOut',JSON.stringify(j.result,null,2));}
  catch(e){setTxt('advOut','Error: '+e.message);}}
async function advCompact(){const db=document.getElementById('advDb').value;const col=document.getElementById('advCol').value;
  if(!confirm('Compact?'))return;
  try{const j=await apiBody('/api/user/db/'+encodeURIComponent(db)+'/col/'+encodeURIComponent(col)+'/compact',{});
    setTxt('advOut',JSON.stringify(j.result,null,2));}
  catch(e){setTxt('advOut','Error: '+e.message);}}

function render_utils(){
  setContent('<div class="card" style="border-color:rgba(255,34,85,.4);">' +
    '<div class="card-title"><span class="ico" style="color:#FF3B5C;">🔒</span>Restricted' +
    '<span class="badge restricted" style="margin-left:auto;">MASTER + GM</span></div>' +
    '<div class="hint danger">Sealed to master and grandmaster only.</div></div>' +
    '<div class="card"><div class="card-title"><span class="ico">🌐</span>IP Lookup</div>' +
    '<div class="row"><input class="input grow" id="ipInput" placeholder="8.8.8.8 (blank = yours)">' +
    '<button class="btn primary" onclick="lookupIp()">Lookup</button></div>' +
    '<div class="code" id="ipOut" style="margin-top:12px;"></div></div>' +
    '<div class="card"><div class="card-title"><span class="ico">📍</span>PIN Code (India)</div>' +
    '<div class="row"><input class="input grow" id="pinInput" placeholder="400001" maxlength="6">' +
    '<button class="btn primary" onclick="lookupPincode()">Lookup</button></div>' +
    '<div class="code" id="pinOut" style="margin-top:12px;"></div></div>');
}
async function lookupIp(ip){
  const el=document.getElementById('ipInput');
  ip = ip || (el ? el.value.trim() : '');
  try{
    const j = await api('/api/util/ip' + (ip ? ('?ip=' + encodeURIComponent(ip)) : ''));
    const out = document.getElementById('ipOut');
    if(out) out.innerHTML = renderIpResult(j);
    else showIpModal(ip || j.query || 'your IP', j);
  }catch(e){showAlert('IP: '+e.message,'error');}
}
function renderIpResult(j){
  if(j.error) return '<div class="hint danger" style="margin:0;">'+esc(j.error)+'</div>';
  const zipField = j.zip || ''; const lookupCode = zipField;
  const lines = [
    'IP:          ' + (j.query || j.ip || '—'),
    'Country:     ' + (j.country || '—') + ' (' + (j.countryCode || '—') + ')',
    'Region:      ' + (j.regionName || j.region || '—'),
    'City:        ' + (j.city || '—'),
  ];
  if(zipField) lines.push('ZIP:         ' + zipField);
  lines.push('Lat/Lon:     ' + (j.lat||'—') + ', ' + (j.lon||'—'));
  lines.push('Timezone:    ' + (j.timezone || '—'));
  lines.push('ISP:         ' + (j.isp || '—'));
  lines.push('Org:         ' + (j.org || '—'));
  lines.push('ASN:         ' + (j.as || '—'));
  lines.push('Reverse:     ' + (j.reverse || '—'));
  lines.push('Source:      ' + (j._source || 'unknown'));
  const flags = [];
  if(j.mobile) flags.push('📱 mobile');
  if(j.proxy) flags.push('🛡 proxy');
  if(j.hosting) flags.push('☁ hosting');
  if(flags.length) lines.push('Flags:       ' + flags.join(' · '));
  let html = '<pre style="margin:0;color:#00ED64;white-space:pre-wrap;word-break:break-all;font-family:JetBrains Mono,monospace;font-size:12px;">' + esc(lines.join('\n')) + '</pre>';
  if(lookupCode && /^\d{6}$/.test(lookupCode)){
    html += '<div style="margin-top:14px;padding-top:14px;border-top:1px solid #1a4d66;">' +
      '<button class="btn primary" onclick="lookupPincodeFromIp(\'' + esc(lookupCode) + '\', this)">📍 PIN code details for ' + esc(lookupCode) + '</button>' +
      '<div id="ipPinOut" class="code" style="margin-top:12px;max-height:0;overflow:hidden;transition:all .3s;padding:0;"></div>' +
      '</div>';
  } else if(lookupCode){
    html += '<div style="margin-top:14px;padding-top:14px;border-top:1px solid #1a4d66;color:#6ba393;font-size:12px;">🌍 ZIP: ' + esc(lookupCode) + ' (only 6-digit India PINs get detailed lookup)</div>';
  }
  return html;
}
async function lookupPincodeFromIp(code, btn){
  var out = document.getElementById('ipPinOut'); if(!out) return;
  if(out.dataset.loaded === '1'){
    if(out.style.maxHeight === '0px'){out.style.maxHeight = '400px'; out.style.padding = '16px';}
    else {out.style.maxHeight = '0px'; out.style.padding = '0';} return;
  }
  out.style.maxHeight = '400px'; out.style.padding = '16px';
  out.textContent = 'Loading PIN ' + code + '...';
  try{ var j = await api('/api/util/pincode?code=' + encodeURIComponent(code));
    out.textContent = JSON.stringify(j, null, 2); out.dataset.loaded = '1';
  }catch(e){ out.textContent = 'Error: ' + e.message; }
}
async function lookupPincode(){
  const code = document.getElementById('pinInput').value.trim();
  if(!/^\d{6}$/.test(code)){showAlert('PIN code must be 6 digits','error');return;}
  try{ const j = await api('/api/util/pincode?code=' + encodeURIComponent(code));
    setTxt('pinOut', JSON.stringify(j, null, 2));
  }catch(e){showAlert('PIN: ' + e.message, 'error');}
}
function showIpModal(ipLabel, j){
  var overlay = document.createElement('div');
  overlay.className = 'uri-modal-overlay';
  var inner = document.createElement('div');
  inner.className = 'uri-modal';
  inner.innerHTML = '<div class="uri-modal-head"><div class="title">🌐 IP — '+esc(ipLabel)+'</div>' +
    '<button class="close-btn" id="ipCloseBtn">✕</button></div>' +
    '<div class="code" style="max-height:none;">'+renderIpResult(j)+'</div>';
  overlay.appendChild(inner); document.body.appendChild(overlay);
  overlay.querySelector('#ipCloseBtn').onclick=function(){overlay.remove();};
  overlay.addEventListener('click',function(e){if(e.target===overlay)overlay.remove();});
}

function render_master(){
  setContent('<div class="grid cols-3" id="masterStats">'+empty('⏳','Loading...')+'</div>' +
    '<div class="card"><div class="card-title">Quick Downloads</div>' +
    '<div class="row"><button class="btn green" onclick="downloadMasterAll()">⬇ Master Cluster ZIP</button>' +
    '<button class="btn primary" onclick="downloadAllDbsZip()">⬇ Active Cluster ZIP</button></div></div>');
  loadMasterStats();
}
async function loadMasterStats(){
  try{const j=await api('/api/master/dashboard');
    setEl('masterStats',
      '<div class="stat"><span class="num">'+j.total_users+'</span><span class="lbl">Users</span></div>' +
      '<div class="stat blue"><span class="num">'+j.total_devices+'</span><span class="lbl">Devices</span></div>' +
      '<div class="stat amber"><span class="num">'+j.total_visits+'</span><span class="lbl">Visits</span></div>' +
      '<div class="stat purple"><span class="num">'+j.total_audits+'</span><span class="lbl">Audits</span></div>' +
      '<div class="stat red"><span class="num">'+j.total_login_attempts+'</span><span class="lbl">Logins</span></div>' +
      '<div class="stat"><span class="num">'+j.active_sessions+'</span><span class="lbl">Sessions</span></div>' +
      '<div class="stat purple"><span class="num">'+(j.total_master_uris||0)+'</span><span class="lbl">Vault</span></div>');
  }catch(e){showAlert(e.message,'error');}
}
function render_visitors(){
  setContent('<div class="card"><div class="row" style="margin-bottom:0;">' +
    '<select class="select grow" id="visMode" onchange="renderVisList()">' +
    '<option value="devices">📱 Devices</option>' +
    '<option value="sessions">👣 Sessions</option></select>' +
    '<input class="input grow" id="visSearch" placeholder="Filter..." oninput="renderVisList()">' +
    '<button class="btn ghost" onclick="loadVisitors()">↻</button></div></div>' +
    '<div id="visTable"></div>');
  loadVisitors();
}
async function loadVisitors(){
  try{const j=await api('/api/master/visitors');
    cachedVisitors = j.devices || []; window._cachedSessions = j.sessions || [];
    renderVisList();}
  catch(e){showAlert(e.message,'error');}
}
function renderVisList(){
  const modeEl=document.getElementById('visMode');const searchEl=document.getElementById('visSearch');
  const wrap=document.getElementById('visTable');if(!wrap)return;
  const mode=modeEl?modeEl.value:'devices';const q=(searchEl?searchEl.value:'').toLowerCase();
  if(mode==='sessions'){
    const list=(window._cachedSessions||[]).filter(function(s){
      return !q||((s.ip||'').indexOf(q)!==-1)||((s.device_id||'').indexOf(q)!==-1);});
    wrap.innerHTML='<div class="table-wrap"><table>' +
      '<thead><tr><th>Device ID</th><th>IP</th><th>Path</th><th>Hits</th><th>Last</th><th></th></tr></thead><tbody>' +
      (list.map(function(s){return '<tr><td class="mono">'+esc((s.device_id||'').slice(0,14))+'…</td>' +
        '<td class="mono">'+esc(s.ip||'')+'</td><td>'+esc(s.last_path||'')+'</td>' +
        '<td><span class="pill">'+(s.page_count||0)+'</span></td>' +
        '<td class="muted">'+esc((s.last_seen||'').slice(0,19).replace('T',' '))+'</td>' +
        '<td>'+ipBtn(s.ip)+'</td></tr>';}).join('') || '<tr><td colspan="6">'+empty('👣','No sessions')+'</td></tr>') +
      '</tbody></table></div>';return;
  }
  const list=cachedVisitors.filter(function(v){
    return !q||((v.last_ip||'').indexOf(q)!==-1)||((v.device_hash||'').indexOf(q)!==-1);});
  wrap.innerHTML='<div class="table-wrap"><table>' +
    '<thead><tr><th>Device</th><th>IPs</th><th>Hits</th><th>VIDs</th><th>Last</th><th>Actions</th></tr></thead><tbody>' +
    (list.map(function(v){
      const vidsHtml=(v.vids||[]).length?(v.vids||[]).map(function(id){return '<span class="pill blue">'+esc(id.slice(0,8))+'</span>';}).join(' '):'—';
      return '<tr><td class="mono">'+esc((v.device_hash||'').slice(0,14))+'…</td>' +
      '<td class="mono">'+esc((v.ips||[]).slice(-3).join(', '))+'</td>' +
      '<td><span class="pill">'+(v.hits||0)+'</span></td>' +
      '<td>'+vidsHtml+'</td>' +
      '<td class="muted">'+esc((v.last_seen||'').slice(0,19).replace('T',' '))+'</td>' +
      '<td><div class="row" style="margin:0;gap:5px;flex-wrap:wrap;">'+ipBtn(v.last_ip)+
      '<button class="btn ghost sm" onclick="viewDevice(\''+esc(v.device_hash)+'\')">👁</button></div></td></tr>';}).join('')
      || '<tr><td colspan="6">'+empty('📱','No devices')+'</td></tr>') + '</tbody></table></div>';
}
async function viewDevice(hash){
  try{const j=await api('/api/master/device/'+encodeURIComponent(hash));
    const d=j.device||{};const b=d.browser||{};
    const lines=['═══ DEVICE ═══','Hash:  '+(d.device_hash||''),'First: '+((d.first_seen||'').slice(0,19)),
      'Last:  '+((d.last_seen||'').slice(0,19)),'Hits:  '+(d.hits||0),'','═══ IPs ═══']
      .concat((d.ips||[]).map(function(ip){return '  • '+ip;}))
      .concat(['','═══ BROWSER ═══','UA: '+(b.user_agent||'—'),'Platform: '+(b.platform||'—'),
        'Screen: '+(b.screen||'—'),'TZ: '+(b.timezone||'—')]);
    alert(lines.join('\n'));}
  catch(e){showAlert(e.message,'error');}
}
function render_users(){
  setContent('<div class="card"><div class="row" style="margin-bottom:0;">' +
    '<input class="input grow" id="usrSearch" placeholder="Filter..." oninput="renderUsersList()">' +
    '<button class="btn green" onclick="downloadMasterAll()">⬇ Master ZIP</button>' +
    '<button class="btn ghost" onclick="loadUsers()">↻</button></div></div>' +
    '<div class="table-wrap"><table><thead><tr><th>VID</th><th>URI</th><th>IP</th><th>Conn</th><th>Actions</th></tr></thead>' +
    '<tbody id="usrRows"><tr><td colspan="5">'+empty('⏳','Loading...')+'</td></tr></tbody></table></div>');
  loadUsers();
}
async function loadUsers(){try{const j=await api('/api/master/users');cachedUsers=j.users||[];renderUsersList();}
  catch(e){showAlert(e.message,'error');}}
function renderUsersList(){
  const tb=document.getElementById('usrRows');if(!tb)return;
  const q=(document.getElementById('usrSearch')?document.getElementById('usrSearch').value:'').toLowerCase();
  const list=cachedUsers.filter(function(u){return !q||((u.vid||'').toLowerCase().indexOf(q)!==-1)||((u.ip||'').indexOf(q)!==-1);});
  tb.innerHTML=list.map(function(u){
    return '<tr><td class="mono">'+esc((u.vid||'').slice(0,12))+'…</td>' +
    '<td class="mono muted">'+esc(u.masked_uri||'')+'</td>' +
    '<td class="mono">'+esc(u.ip||'')+'</td>' +
    '<td><span class="pill">'+(u.connect_count||0)+'</span></td>' +
    '<td><div class="row" style="margin:0;gap:5px;flex-wrap:wrap;">'+ipBtn(u.ip)+
    '<button class="btn reveal sm" onclick="revealUri(\''+esc(u.vid)+'\')">🔓</button>' +
    (ROLE==='grandmaster'
      ? '<button class="btn sm" onclick="impersonate(\''+esc(u.vid)+'\')">🎭</button>' +
        '<button class="btn danger sm" onclick="delUser(\''+esc(u.vid)+'\')">🗑</button>'
      : '') + '</div></td></tr>';}).join('') || '<tr><td colspan="5">'+empty('🔑','No users')+'</td></tr>';
}
async function revealUri(vid){
  try{const j=await api('/api/master/reveal-uri/'+encodeURIComponent(vid));
    const uri=j.uri||'';
    var overlay=document.createElement('div');overlay.className='uri-modal-overlay';
    var inner=document.createElement('div');inner.className='uri-modal';
    inner.innerHTML='<div class="uri-modal-head"><div class="title">🔓 FULL URI</div>' +
      '<button class="close-btn" id="uriCloseBtn">✕</button></div>' +
      '<div class="hint danger">⚠ Credentials inside.</div>' +
      '<textarea readonly id="uriFullText">'+esc(uri)+'</textarea>' +
      '<button id="uriCopyBtn" class="btn reveal full" style="margin-top:14px;">📋 Copy URI</button>' +
      '<div id="uriTestOut" class="code" style="margin-top:12px;display:none;"></div>';
    overlay.appendChild(inner);document.body.appendChild(overlay);
    overlay.querySelector('#uriCloseBtn').onclick=function(){overlay.remove();};
    overlay.addEventListener('click',function(e){if(e.target===overlay)overlay.remove();});
    overlay.querySelector('#uriCopyBtn').onclick=function(){
      const txt=overlay.querySelector('#uriFullText');txt.select();txt.setSelectionRange(0,999999);
      try{if(navigator.clipboard)navigator.clipboard.writeText(uri).then(function(){showAlert('✅ Copied','success',3000);}).catch(function(){document.execCommand('copy');showAlert('✅ Copied','success',3000);});
        else{document.execCommand('copy');showAlert('✅ Copied','success',3000);}}
      catch(e){showAlert('Copy failed: '+e.message,'error');}};
  }catch(e){showAlert(e.message,'error');}
}
async function delUser(vid){if(!confirm('Delete '+vid+'?'))return;
  try{await api('/api/gm/delete-user/'+encodeURIComponent(vid),{method:'DELETE'});showAlert('Deleted','success');loadUsers();}
  catch(e){showAlert(e.message,'error');}}
async function impersonate(vid){if(!confirm('Impersonate?'))return;
  try{const j=await apiBody('/api/gm/impersonate/'+encodeURIComponent(vid),{});
    localStorage.setItem('vid',j.vid);localStorage.setItem('role','user');
    showAlert('Impersonating...','success');setTimeout(function(){location.reload();},1000);}
  catch(e){showAlert(e.message,'error');}}
function render_logins(){
  setContent('<div class="card"><div class="row" style="margin-bottom:0;">' +
    '<button class="btn ghost" onclick="loadLogins()">↻</button></div></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Identifier</th><th>Role</th><th>Status</th><th>IP</th><th>Time</th><th></th></tr></thead>' +
    '<tbody id="loginRows"><tr><td colspan="6">'+empty('⏳','Loading...')+'</td></tr></tbody></table></div>');
  loadLogins();
}
async function loadLogins(){
  try{const j=await api('/api/master/login-attempts');
    setEl('loginRows',((j.attempts||[]).map(function(a){
      return '<tr><td>'+esc(a.identifier||'')+'</td>' +
      '<td><span class="badge '+(a.role||'user')+'">'+esc(a.role||'')+'</span></td>' +
      '<td><span class="badge '+(a.success?'ok':'bad')+'">'+(a.success?'✓':'✗')+'</span></td>' +
      '<td class="mono">'+esc(a.ip)+'</td>' +
      '<td class="muted">'+esc((a.timestamp||'').slice(0,19).replace('T',' '))+'</td>' +
      '<td>'+ipBtn(a.ip)+'</td></tr>';}).join('') || '<tr><td colspan="6">'+empty('🔐','None')+'</td></tr>'));}
  catch(e){showAlert(e.message,'error');}
}
function render_audits(){
  setContent('<div class="card"><button class="btn ghost" onclick="loadAudits()">↻</button></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Action</th><th>User</th><th>IP</th><th>Time</th><th>Details</th><th></th></tr></thead>' +
    '<tbody id="auditRows"><tr><td colspan="6">'+empty('⏳','Loading...')+'</td></tr></tbody></table></div>');
  loadAudits();
}
async function loadAudits(){
  try{const j=await api('/api/master/audits');
    setEl('auditRows',((j.audits||[]).map(function(a){
      return '<tr><td><span class="pill">'+esc(a.action)+'</span></td>' +
      '<td>'+esc(a.user)+'</td><td class="mono">'+esc(a.ip)+'</td>' +
      '<td class="muted">'+esc((a.timestamp||'').slice(0,19).replace('T',' '))+'</td>' +
      '<td class="mono muted">'+esc(JSON.stringify(a.details||{}).slice(0,60))+'</td>' +
      '<td>'+ipBtn(a.ip)+'</td></tr>';}).join('') || '<tr><td colspan="6">'+empty('📜','None')+'</td></tr>'));}
  catch(e){showAlert(e.message,'error');}
}
function render_storage(){
  setContent('<div class="card"><div class="card-title"><span class="ico">💾</span>Master Cluster Storage' +
    '<button class="btn green sm" style="margin-left:auto;" onclick="downloadMasterAll()">⬇ DOWNLOAD ALL (ZIP)</button>' +
    '<button class="btn ghost sm" onclick="loadStorage()">↻</button></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Database</th><th>Collections</th><th>Docs</th><th>Size</th><th>Storage</th><th>Export</th></tr></thead>' +
    '<tbody id="storageRows"><tr><td colspan="6">'+empty('⏳','Loading...')+'</td></tr></tbody></table></div>');
  loadStorage();
}
async function loadStorage(){
  try{const j=await api('/api/master/storage');
    setEl('storageRows',Object.keys(j.storage||{}).map(function(db){
      const s = j.storage[db];const dbE=esc(db);
      return '<tr><td><strong>'+dbE+'</strong></td>' +
      '<td>'+(s.collections||0)+'</td><td>'+(s.documents||0)+'</td>' +
      '<td>'+fmt(s.size||0)+'</td><td>'+fmt(s.storage||0)+'</td>' +
      '<td><button class="btn green sm" onclick="dlMasterDb(\''+dbE+'\')">⬇ ZIP</button></td></tr>';}).join('')
      || '<tr><td colspan="6">'+empty('💾','Empty')+'</td></tr>');}
  catch(e){showAlert(e.message,'error');}
}
function render_impersonate(){
  setContent('<div class="card"><div class="card-title"><span class="ico">🎭</span>Impersonate User</div>' +
    '<div class="hint">Paste target VID.</div>' +
    '<div class="row"><input class="input grow" id="impVid" placeholder="target VID">' +
    '<button class="btn danger" onclick="doImpersonate()">🎭 Impersonate</button>' +
    '<button class="btn" onclick="doConnectOnly()">🔗 Connect Only</button></div>' +
    '<div class="code" id="impOut" style="margin-top:12px;"></div></div>');
}
async function doImpersonate(){const vid=document.getElementById('impVid').value.trim();if(!vid)return;await impersonate(vid);}
async function doConnectOnly(){const vid=document.getElementById('impVid').value.trim();if(!vid)return;
  try{const j=await api('/api/gm/connect/'+encodeURIComponent(vid));
    setTxt('impOut',JSON.stringify(j,null,2));}
  catch(e){setTxt('impOut','Error: '+e.message);}}
function render_wipe(){
  setContent('<div class="card"><div class="card-title"><span class="ico" style="color:#FF3B5C;">💀</span>Wipe Collection</div>' +
    '<div class="hint danger">Deletes ALL docs. Irreversible.</div>' +
    '<div class="field"><label>Collection</label><select class="select" id="wipeCol">' +
    '<option value="uris">uris</option><option value="visits">visits</option>' +
    '<option value="sessions">sessions</option><option value="devices">devices</option>' +
    '<option value="audits">audits</option><option value="login_attempts">login_attempts</option>' +
    '<option value="master_uris">master_uris</option></select></div>' +
    '<div class="field"><label>Type collection name to confirm</label>' +
    '<input class="input" id="wipeConfirm" placeholder="e.g. uris"></div>' +
    '<button class="btn danger" onclick="doWipe()">💀 Wipe</button>' +
    '<div class="code" id="wipeOut" style="margin-top:12px;"></div></div>');
}
async function doWipe(){
  const col=document.getElementById('wipeCol').value;const conf=document.getElementById('wipeConfirm').value.trim();
  if(conf!==col){showAlert('Mismatch','error');return;}
  try{const j=await apiBody('/api/gm/wipe/'+col,{confirm:conf});
    setTxt('wipeOut','Wiped '+j.deleted+' from '+col);
    showAlert('Wiped','success');}
  catch(e){showAlert(e.message,'error');}
}

async function loadDbsForSelect(id, onLoad){
  const sel=document.getElementById(id);if(!sel)return;
  try{const j=await api('/api/user/databases');cachedDbs=j.databases||[];
    const opts = cachedDbs.length ? cachedDbs.map(function(d){return '<option value="'+esc(d.name)+'">'+esc(d.name)+'</option>';}).join('') : '<option value="">(no databases)</option>';
    if(id==='urDb'){ sel.innerHTML = '<option value="admin">admin</option>'+opts; }
    else { sel.innerHTML=opts; }
    if(onLoad)onLoad();}
  catch(e){sel.innerHTML='<option value="">(error)</option>';}
}
async function loadColsForSelect(dbSelId, colSelId, onLoad){
  const dbEl=document.getElementById(dbSelId);const colSel=document.getElementById(colSelId);
  if(!dbEl||!colSel)return;const db=dbEl.value;if(!db)return;
  try{const j=await api('/api/user/db/'+encodeURIComponent(db)+'/collections');
    const cols=j.collections||[];
    colSel.innerHTML=cols.length ? cols.map(function(c){return '<option value="'+esc(c.name)+'">'+esc(c.name)+' ('+c.count+')</option>';}).join('') : '<option value="">(none)</option>';
    if(onLoad)onLoad();}
  catch(e){colSel.innerHTML='<option value="">(error)</option>';}
}

document.addEventListener('change', function(e){
  const id=e.target.id;
  if(id==='colDbSelect')loadCollections();
  if(id==='docDbSelect')loadColsForSelect('docDbSelect','docColSelect');
  if(id==='maskDb')loadColsForSelect('maskDb','maskCol');
  if(id==='ioDb')loadColsForSelect('ioDb','ioCol');
  if(id==='chDb')loadColsForSelect('chDb','chCol');
  if(id==='dangerDb')loadColsForSelect('dangerDb','dangerCol');
  if(id==='dlDbSel')loadColsForSelect('dlDbSel','dlColSel');
});

(function init(){
  if(!VID){location.href='/superadmin';return;}
  document.getElementById('roleDot').className='dot '+ROLE;
  document.getElementById('roleValue').textContent=ROLE.toUpperCase();
  document.getElementById('topBadge').className='badge '+ROLE;
  document.getElementById('topBadge').textContent=ROLE.toUpperCase();
  api('/api/me').then(function(me){
    if(me.impersonating)document.getElementById('pageSub').textContent='Impersonating — '+(me.masked_uri||'');
  }).catch(function(e){showAlert('Session: '+e.message,'error');});
  buildNav();
})();
</script>
''' + VOID_SHIELD_JS + FINGERPRINT_JS + r'''
</body></html>'''

@app.route('/dashboard')
def page_dashboard():
    return render_template_string(DASHBOARD_HTML)

# ═══════════════════════════════════════════════
# BOOT
# ═══════════════════════════════════════════════
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    logger.info("═" * 60)
    logger.info("🥭 TOCXIC v78 — DB sessions · /superadmin · no timeout")
    logger.info(f"✓ /            → landing")
    logger.info(f"✓ /connect     → user URI connect")
    logger.info(f"✓ /superadmin  → admin login (only entry)")
    logger.info(f"✓ /superadmin/owner-panel  → owner console")
    logger.info(f"✓ /dashboard   → main dashboard")
    logger.info(f"✓ Port: {port}")
    logger.info("═" * 60)
    try: get_master_client()
    except Exception as e: logger.warning(f"master pre-warm: {e}")
    try: _owner_ensure_admin()
    except Exception as e: logger.warning(f"owner admin: {e}")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
