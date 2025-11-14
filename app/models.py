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