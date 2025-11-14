import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

import motor.motor_asyncio
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import jwt, JWTError
from starlette.middleware.cors import CORSMiddleware

# ---------- logging ----------
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
# ---------------------------
# CONFIG
# ---------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

MONGODB_URI = os.getenv("MONGODB_URI")
DB_NAME = os.getenv("DB_NAME", "mydb")

if not MONGODB_URI:
    logger.warning("MONGODB_URI not set. Set it in .env or environment for DB access.")

# ---------------------------
# Initialize services
# ---------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
db = client[DB_NAME]
users_col = db["users"]
shipments_col = db["shipments"]
device_data_col = db["device_data"]

app = FastAPI(title="SCMXperLite_Architecture")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    id: str = Field(..., alias="_id")
    email: str
    full_name: Optional[str] = None

class LoginIn(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class ShipmentIn(BaseModel):
    tracking_id: Optional[str] = None
    origin: str
    destination: str
    weight_kg: Optional[float] = None
    metadata: Optional[dict] = None

class ShipmentOut(ShipmentIn):
    id: str
    created_at: datetime

class DeviceDataIn(BaseModel):
    device_id: str
    timestamp: Optional[datetime] = None
    payload: dict

class DeviceDataOut(DeviceDataIn):
    id: str
    created_at: datetime

# ---------------------------
# Utilities
# ---------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def make_jwt(sub: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode = {"sub": sub, "exp": expire, "type": "access"}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_user_by_email(email: str):
    return await users_col.find_one({"email": email})

async def get_user_by_id(user_id: str):
    return await users_col.find_one({"_id": user_id})

# ---------------------------
# Auth: register / login
# ---------------------------
@app.post("/register", response_model=UserOut, status_code=201)
async def register(payload: UserIn):
    logger.debug("Register called with payload: %s", payload.dict())
    try:
        email = payload.email.lower()
        existing = await users_col.find_one({"email": email})

        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")

        user_doc = {
            "_id": str(uuid.uuid4()),
            "email": email,
            "full_name": payload.full_name,
            "password_hash": hash_password(payload.password),
            "created_at": datetime.utcnow(),
        }

        await users_col.insert_one(user_doc)

        return {
            "_id": user_doc["_id"],
            "email": user_doc["email"],
            "full_name": user_doc["full_name"]
        }

    except Exception as e:
        logger.exception("Error in /register")
        raise


@app.post("/login", response_model=TokenResponse)
async def login(payload: LoginIn):
    user = await get_user_by_email(payload.email.lower())
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = make_jwt(user["_id"])
    return TokenResponse(access_token=access_token, expires_in=int(ACCESS_TOKEN_EXPIRE_MINUTES * 60))

# ---------------------------
# Auth dependency
# ---------------------------
async def validate_access_token(authorization: str = Header(..., alias="Authorization")):
    """
    Expect: Authorization: Bearer <token>
    Returns user dict.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth header")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Not an access token")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Malformed token")
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ---------------------------
# Protected: create shipment
# ---------------------------
@app.post("/shipments", response_model=ShipmentOut, status_code=201)
async def create_shipment(payload: ShipmentIn, user=Depends(validate_access_token)):
    doc = {
        "_id": str(uuid.uuid4()),
        "user_id": user["_id"],
        "tracking_id": payload.tracking_id or str(uuid.uuid4())[:12],
        "origin": payload.origin,
        "destination": payload.destination,
        "weight_kg": payload.weight_kg,
        "metadata": payload.metadata or {},
        "created_at": datetime.utcnow(),
    }
    await shipments_col.insert_one(doc)
    return ShipmentOut(id=doc["_id"], tracking_id=doc["tracking_id"], origin=doc["origin"],
                       destination=doc["destination"], weight_kg=doc["weight_kg"],
                       metadata=doc["metadata"], created_at=doc["created_at"])

# ---------------------------
# Protected: create device data
# ---------------------------
@app.post("/device-data", response_model=DeviceDataOut, status_code=201)
async def create_device_data(payload: DeviceDataIn, request: Request, user=Depends(validate_access_token)):
    ts = payload.timestamp or datetime.utcnow()
    doc = {
        "_id": str(uuid.uuid4()),
        "user_id": user["_id"],
        "device_id": payload.device_id,
        "timestamp": ts,
        "payload": payload.payload,
        "created_at": datetime.utcnow(),
        "source_ip": request.client.host if request.client else None,
    }
    await device_data_col.insert_one(doc)
    return DeviceDataOut(id=doc["_id"], device_id=doc["device_id"], timestamp=doc["timestamp"],
                         payload=doc["payload"], created_at=doc["created_at"])

# ---------------------------
# Simple health root
# ---------------------------
@app.get("/", response_class=JSONResponse)
async def root():
    return {"ok": True, "msg": "API running. Use /docs for interactive docs."}
