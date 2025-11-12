import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, List

import motor.motor_asyncio
from fastapi import FastAPI, Depends, HTTPException, status, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from starlette.middleware.cors import CORSMiddleware

# ---------------------------
# CONFIG (use env vars in prod)
# ---------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "fastapi_auth_db")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def root():
    return "<h2>FastAPI is up — go to <a href='/docs'>/docs</a></h2>"

# ---------------------------
# Mongo (Motor)
# ---------------------------
client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
db = client[DB_NAME]
users_col = db["users"]
sessions_col = db["sessions"]

# Ensure useful indexes in background for sessions (optional)
# e.g. sessions_col.create_index("user_id"); done in migration in prod

# ---------------------------
# FastAPI app
# ---------------------------
app = FastAPI(title="FastAPI Auth with MongoDB Sessions")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Pydantic models
# ---------------------------
class UserIn(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None

class UserOut(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str

class RefreshRequest(BaseModel):
    refresh_token: str

class SessionOut(BaseModel):
    id: str = Field(..., alias="_id")
    user_id: str
    device: Optional[str]
    ip: Optional[str]
    created_at: datetime
    expires_at: datetime
    revoked: bool

# ---------------------------
# Utilities
# ---------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def make_jwt(payload: dict, expires_delta: timedelta) -> str:
    to_encode = payload.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

async def get_user_by_email(email: str):
    return await users_col.find_one({"email": email})

async def get_user_by_id(user_id: str):
    return await users_col.find_one({"_id": user_id})

# ---------------------------
# Auth flows: register / login / refresh / logout
# ---------------------------
@app.post("/register", response_model=UserOut, status_code=201)
async def register(payload: UserIn):
    existing = await users_col.find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "_id": str(uuid.uuid4()),
        "email": payload.email.lower(),
        "full_name": payload.full_name,
        "password_hash": hash_password(payload.password),
        "created_at": datetime.utcnow(),
    }
    await users_col.insert_one(user_doc)
    return UserOut(id=user_doc["_id"], email=user_doc["email"], full_name=user_doc["full_name"])

@app.post("/login", response_model=TokenResponse)
async def login(payload: UserIn, request: Request, user_agent: Optional[str] = Header(None)):
    # authenticate
    user = await get_user_by_email(payload.email.lower())
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # create a session
    session_id = str(uuid.uuid4())
    now = datetime.utcnow()
    session_expires = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    session_doc = {
        "_id": session_id,
        "user_id": user["_id"],
        "device": user_agent or "unknown",
        "ip": request.client.host if request.client else None,
        "created_at": now,
        "expires_at": session_expires,
        "revoked": False,
        # store optionally last rotated refresh jti to prevent reuse on rotation
        "current_refresh_jti": None,
    }
    await sessions_col.insert_one(session_doc)

    # issue tokens: include session id (sid) in both tokens
    access_jti = str(uuid.uuid4())
    refresh_jti = str(uuid.uuid4())
    access_token = make_jwt(
        {"sub": user["_id"], "sid": session_id, "jti": access_jti, "type": "access"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = make_jwt(
        {"sub": user["_id"], "sid": session_id, "jti": refresh_jti, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    # save current refresh_jti to session for rotation checks
    await sessions_col.update_one({"_id": session_id}, {"$set": {"current_refresh_jti": refresh_jti}})

    return TokenResponse(
        access_token=access_token,
        expires_in=int(ACCESS_TOKEN_EXPIRE_MINUTES * 60),
        refresh_token=refresh_token,
    )

# ---------------------------
# Token validation dependency
# ---------------------------
async def validate_access_token(token: str = Header(..., alias="Authorization")):
    """
    Expect header: Authorization: Bearer <token>
    This dependency decodes token, checks type, session exists and not revoked/expired.
    Returns dict with claims.
    """
    if not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth header")
    token = token.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # check it's an access token
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Token is not access token")

    user_id = payload.get("sub")
    sid = payload.get("sid")
    if not user_id or not sid:
        raise HTTPException(status_code=401, detail="Malformed token")

    # load session and check
    session = await sessions_col.find_one({"_id": sid})
    if not session:
        raise HTTPException(status_code=401, detail="Session does not exist")
    if session.get("revoked"):
        raise HTTPException(status_code=401, detail="Session revoked")
    if datetime.utcnow() > session.get("expires_at"):
        raise HTTPException(status_code=401, detail="Session expired")

    # Optionally check jti or access token reuse logic here
    # For now, we rely on session revocation + expiry to invalidate access tokens.

    return {"user_id": user_id, "sid": sid, "claims": payload}

async def get_current_user(claims = Depends(validate_access_token)):
    user = await get_user_by_id(claims["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ---------------------------
# Protected route example
# ---------------------------
@app.get("/me", response_model=UserOut)
async def me(user=Depends(get_current_user)):
    return UserOut(id=user["_id"], email=user["email"], full_name=user.get("full_name"))

# ---------------------------
# Refresh token endpoint (rotation)
# ---------------------------
@app.post("/token/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshRequest, request: Request, user_agent: Optional[str] = Header(None)):
    token = req.refresh_token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Token not a refresh token")
    user_id = payload.get("sub")
    sid = payload.get("sid")
    jti = payload.get("jti")
    if not user_id or not sid:
        raise HTTPException(status_code=401, detail="Malformed refresh token")

    session = await sessions_col.find_one({"_id": sid})
    if not session:
        raise HTTPException(status_code=401, detail="Session not found")
    if session.get("revoked"):
        raise HTTPException(status_code=401, detail="Session revoked")
    if datetime.utcnow() > session.get("expires_at"):
        raise HTTPException(status_code=401, detail="Session expired")

    # Prevent reuse of old refresh token by verifying jti matches session's current_refresh_jti
    current_refresh_jti = session.get("current_refresh_jti")
    if current_refresh_jti is None or current_refresh_jti != jti:
        # token reuse / stolen refresh token (rotated) — revoke session to be safe
        await sessions_col.update_one({"_id": sid}, {"$set": {"revoked": True}})
        raise HTTPException(status_code=401, detail="Refresh token reuse detected — session revoked")

    # rotation: issue new refresh token, update session current_refresh_jti
    new_refresh_jti = str(uuid.uuid4())
    new_access_jti = str(uuid.uuid4())
    access_token = make_jwt(
        {"sub": user_id, "sid": sid, "jti": new_access_jti, "type": "access"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = make_jwt(
        {"sub": user_id, "sid": sid, "jti": new_refresh_jti, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    # update session current_refresh_jti (atomic)
    await sessions_col.update_one(
        {"_id": sid},
        {"$set": {"current_refresh_jti": new_refresh_jti, "device": user_agent or session.get("device")}},
    )

    return TokenResponse(
        access_token=access_token,
        expires_in=int(ACCESS_TOKEN_EXPIRE_MINUTES * 60),
        refresh_token=refresh_token,
    )

# ---------------------------
# Session management endpoints
# ---------------------------
@app.get("/sessions", response_model=List[SessionOut])
async def list_sessions(user=Depends(get_current_user)):
    cursor = sessions_col.find({"user_id": user["_id"]}).sort("created_at", -1)
    sessions = []
    async for s in cursor:
        sessions.append(SessionOut(**s))
    return sessions

@app.post("/sessions/{session_id}/revoke")
async def revoke_session(session_id: str, user=Depends(get_current_user)):
    s = await sessions_col.find_one({"_id": session_id})
    if not s or s["user_id"] != user["_id"]:
        raise HTTPException(status_code=404, detail="Session not found")
    await sessions_col.update_one({"_id": session_id}, {"$set": {"revoked": True}})
    return {"ok": True, "msg": "Session revoked"}

@app.post("/sessions/revoke_all")
async def revoke_all_sessions(user=Depends(get_current_user)):
    await sessions_col.update_many({"user_id": user["_id"]}, {"$set": {"revoked": True}})
    return {"ok": True, "msg": "All sessions revoked"}

@app.post("/logout")
async def logout(claims = Depends(validate_access_token)):
    # revoke the session associated with the access token
    sid = claims["sid"]
    await sessions_col.update_one({"_id": sid}, {"$set": {"revoked": True}})
    return {"ok": True, "msg": "Logged out from session"}

# ---------------------------
# Optional: admin / housekeeping
# ---------------------------
@app.post("/cleanup_expired_sessions")
async def cleanup_expired():
    res = await sessions_col.delete_many({"expires_at": {"$lt": datetime.utcnow()}})
    return {"deleted": res.deleted_count}
