"""
FastAPI Backend for Recovery System
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Depends, status, Request, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, validator
import os
from database import db
import logging
from cryptography.fernet import Fernet
import base64
from io import BytesIO
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Private Recovery System API",
    description="Secure remote recovery and automation system",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to your domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    max_age=3600,
)

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key())
fernet = Fernet(ENCRYPTION_KEY)

# Pydantic Models
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    device_id: str = Field(..., min_length=10)

class UserLogin(BaseModel):
    username: str
    password: str
    device_id: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str

class FileMetadata(BaseModel):
    filename: str
    path: str
    size_bytes: int
    mime_type: str
    category: str

class RecoveryAction(BaseModel):
    action_type: str
    parameters: Dict[str, Any]
    requires_confirmation: bool = True

class ActionConfirmation(BaseModel):
    action_id: str
    confirm: bool

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def encrypt_data(data: str) -> str:
    """Encrypt sensitive data"""
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data"""
    return fernet.decrypt(encrypted_data.encode()).decode()

# Dependency: Get current user from token
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), request: Request = None):
    token = credentials.credentials
    device_id = request.headers.get("X-Device-ID") if request else None
    
    if not device_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device ID required"
        )
    
    try:
        # Decode token
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        token_type = payload.get("type")
        
        if not user_id or token_type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Validate session in database
        session = db.validate_session(token, device_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid"
            )
        
        # Get user
        user = db.db.users.find_one({"_id": user_id})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return {
            "id": str(user["_id"]),
            "username": user["username"],
            "device_id": user["device_id"]
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    path = request.url.path
    
    # Simple rate limiting - in production, use Redis
    rate_limit_key = f"rate_limit:{client_ip}:{path}"
    
    # Skip rate limiting for health check
    if path == "/health":
        return await call_next(request)
    
    # Implement proper rate limiting logic here
    response = await call_next(request)
    return response

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected" if db.ping() else "disconnected"
    }

# Authentication endpoints
@app.post("/register", response_model=Dict[str, str])
async def register(user_data: UserRegister):
    """Register a new user and device"""
    
    # Check if username exists
    existing_user = db.get_user_by_username(user_data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # Check if device is already registered
    existing_device = db.get_user_by_device_id(user_data.device_id)
    if existing_device:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device already registered"
        )
    
    # Hash password
    password_hash = get_password_hash(user_data.password)
    
    # Create user
    user_id = db.create_user(user_data.username, password_hash, user_data.device_id)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )
    
    return {"message": "Registration successful", "user_id": user_id}

@app.post("/login", response_model=Token)
async def login(login_data: UserLogin, request: Request):
    """Login and get access tokens"""
    
    # Get user
    user = db.get_user_by_username(login_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify password
    if not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify device
    if user["device_id"] != login_data.device_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device not authorized"
        )
    
    # Update last login
    db.update_last_login(str(user["_id"]))
    
    # Create tokens
    access_token = create_access_token(data={"sub": str(user["_id"])})
    refresh_token = create_refresh_token(data={"sub": str(user["_id"])})
    
    # Create session
    ip_address = request.client.host
    db.create_session(
        user_id=str(user["_id"]),
        token=access_token,
        device_id=login_data.device_id,
        ip_address=ip_address,
        expires_in_minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "refresh_token": refresh_token
    }

@app.post("/logout")
async def logout(current_user: dict = Depends(get_current_user), 
                 credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Logout and invalidate session"""
    token = credentials.credentials
    db.invalidate_session(token)
    return {"message": "Logged out successfully"}

@app.post("/refresh")
async def refresh_token(refresh_token: str, device_id: str):
    """Refresh access token using refresh token"""
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        token_type = payload.get("type")
        
        if not user_id or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Verify user exists
        user = db.db.users.find_one({"_id": user_id})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        # Create new access token
        new_access_token = create_access_token(data={"sub": str(user["_id"])})
        
        # Create new session
        db.create_session(
            user_id=str(user["_id"]),
            token=new_access_token,
            device_id=device_id,
            ip_address="0.0.0.0",  # IP not available in refresh
            expires_in_minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

# File management endpoints
@app.post("/files/upload-metadata")
async def upload_file_metadata(
    metadata: FileMetadata,
    current_user: dict = Depends(get_current_user)
):
    """Upload file metadata (not the actual file)"""
    
    # Generate encryption key for this file
    file_key = Fernet.generate_key()
    encrypted_key = encrypt_data(base64.b64encode(file_key).decode())
    
    # Store metadata
    file_id = db.store_file_metadata(
        user_id=current_user["id"],
        filename=metadata.filename,
        path=metadata.path,
        size_bytes=metadata.size_bytes,
        mime_type=metadata.mime_type,
        category=metadata.category,
        encrypted_key=encrypted_key
    )
    
    return {
        "file_id": file_id,
        "message": "File metadata stored",
        "encryption_key": base64.b64encode(file_key).decode()  # Return once for client
    }

@app.get("/files/list")
async def list_files(
    category: Optional[str] = None,
    limit: int = 100,
    skip: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """List files for the current user"""
    
    files = db.get_user_files(
        user_id=current_user["id"],
        category=category,
        limit=limit,
        skip=skip
    )
    
    # Remove encryption key from response
    for file in files:
        file.pop("encrypted_key", None)
    
    return {
        "files": files,
        "total": len(files),
        "category": category
    }

@app.get("/files/{file_id}/download-url")
async def generate_download_url(
    file_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Generate a temporary signed URL for file download"""
    
    # Get file metadata
    file = db.get_file_by_id(file_id, current_user["id"])
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Create signed token for this download
    download_token = jwt.encode(
        {
            "file_id": file_id,
            "user_id": current_user["id"],
            "exp": datetime.utcnow() + timedelta(minutes=5),
            "purpose": "download"
        },
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )
    
    # In production, this would return a URL to your file storage
    # For this implementation, we return a token the client can use
    return {
        "download_token": download_token,
        "expires_in": 300,  # 5 minutes
        "filename": file["filename"],
        "size_bytes": file["size_bytes"]
    }

# Recovery actions endpoints
@app.post("/actions/create")
async def create_recovery_action(
    action: RecoveryAction,
    current_user: dict = Depends(get_current_user)
):
    """Create a new recovery action requiring confirmation"""
    
    action_id = db.log_recovery_action(
        user_id=current_user["id"],
        action_type=action.action_type,
        parameters=action.parameters,
        initiated_by="remote",  # or "local" for self-initiated
        status="pending" if action.requires_confirmation else "approved"
    )
    
    return {
        "action_id": action_id,
        "requires_confirmation": action.requires_confirmation,
        "message": "Action created successfully"
    }

@app.get("/actions/pending")
async def get_pending_actions(
    current_user: dict = Depends(get_current_user)
):
    """Get pending actions requiring confirmation"""
    
    actions = db.get_pending_actions(current_user["id"])
    
    return {
        "actions": actions,
        "count": len(actions)
    }

@app.post("/actions/confirm")
async def confirm_action(
    confirmation: ActionConfirmation,
    current_user: dict = Depends(get_current_user)
):
    """Confirm or deny a pending action"""
    
    if confirmation.confirm:
        confirmed = db.confirm_action(confirmation.action_id, current_user["id"])
        if not confirmed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Action not found or already processed"
            )
        
        return {"message": "Action confirmed", "status": "confirmed"}
    else:
        # Mark as denied
        db.update_action_status(confirmation.action_id, "denied")
        return {"message": "Action denied", "status": "denied"}

# Device status endpoint
@app.get("/device/status")
async def get_device_status(current_user: dict = Depends(get_current_user)):
    """Get current device status and pending actions"""
    
    pending_actions = db.get_pending_actions(current_user["id"])
    
    return {
        "device_id": current_user["device_id"],
        "username": current_user["username"],
        "pending_actions": len(pending_actions),
        "last_update": datetime.utcnow().isoformat(),
        "status": "online"
    }

# Webhook for Termux to report status (simplified)
@app.post("/device/heartbeat")
async def device_heartbeat(
    status_data: Dict[str, Any],
    current_user: dict = Depends(get_current_user)
):
    """Receive heartbeat from device"""
    
    # Log heartbeat
    db.db.device_heartbeats.insert_one({
        "user_id": current_user["id"],
        "device_id": current_user["device_id"],
        "timestamp": datetime.utcnow(),
        "battery_level": status_data.get("battery_level"),
        "storage_free": status_data.get("storage_free"),
        "network_status": status_data.get("network_status")
    })
    
    # Check for pending actions
    pending_actions = db.get_pending_actions(current_user["id"])
    
    return {
        "pending_actions": [{"id": a["_id"], "type": a["action_type"]} for a in pending_actions],
        "timestamp": datetime.utcnow().isoformat()
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
