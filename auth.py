"""認證相關:JWT、密碼雜湊、防暴力破解、role 檢查。

從 main.py 抽出,由各 route module import 使用。
"""
import os
import time
from datetime import datetime, timedelta
from typing import Optional

import bcrypt as _bcrypt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel


# ── 設定
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

security = HTTPBearer()


# ── Pydantic 模型
class LoginRequest(BaseModel):
    uid: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    name: str
    uid: str


class AdminResetPassword(BaseModel):
    new_password: str


class ChangePassword(BaseModel):
    old_password: str
    new_password: str


# ── 防暴力破解:同一帳號+IP 短時間內試錯太多次即暫時鎖定
_LOGIN_FAILS: dict[str, list[float]] = {}
LOGIN_MAX_FAILS = 8            # 視窗內允許的失敗次數
LOGIN_WINDOW_SEC = 600         # 統計視窗(10 分鐘)
LOGIN_LOCK_SEC = 600           # 觸發後鎖定時間(10 分鐘)


def login_key(uid: str, ip: str) -> str:
    return f"{(uid or '').strip().lower()}|{ip}"


def login_is_locked(key: str) -> int:
    """回傳剩餘鎖定秒數(0=未鎖定)。"""
    now = time.time()
    fails = [t for t in _LOGIN_FAILS.get(key, []) if now - t < LOGIN_WINDOW_SEC]
    _LOGIN_FAILS[key] = fails
    if len(fails) >= LOGIN_MAX_FAILS:
        remain = int(LOGIN_LOCK_SEC - (now - fails[-1]))
        return max(0, remain)
    return 0


def login_record_fail(key: str) -> None:
    _LOGIN_FAILS.setdefault(key, []).append(time.time())


def login_clear(key: str) -> None:
    _LOGIN_FAILS.pop(key, None)


# ── 密碼工具
def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


def get_password_hash(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()


# ── JWT
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        uid = payload.get("sub")
        if uid is None:
            raise HTTPException(status_code=401, detail="無效的 Token")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token 已過期或無效")


def require_roles(*roles):
    def checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="權限不足")
        return current_user
    return checker
