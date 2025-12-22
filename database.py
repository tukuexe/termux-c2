"""
MongoDB Database Connection and Models
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pymongo import MongoClient, IndexModel, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError
import os
from bson import ObjectId
import logging

logger = logging.getLogger(__name__)

class MongoDB:
    """MongoDB Connection Handler"""
    
    def __init__(self):
        self.mongodb_uri = os.getenv("MONGODB_URI")
        if not self.mongodb_uri:
            raise ValueError("MONGODB_URI environment variable not set")
        
        self.client = MongoClient(self.mongodb_uri)
        self.db = self.client.recovery_system
        self._setup_indexes()
        
    def _setup_indexes(self):
        """Create necessary database indexes"""
        # Users collection
        self.db.users.create_indexes([
            IndexModel([("username", ASCENDING)], unique=True),
            IndexModel([("device_id", ASCENDING)], unique=True),
            IndexModel([("created_at", DESCENDING)])
        ])
        
        # Sessions collection
        self.db.sessions.create_indexes([
            IndexModel([("token", ASCENDING)], unique=True),
            IndexModel([("user_id", ASCENDING)]),
            IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0),
            IndexModel([("device_id", ASCENDING)])
        ])
        
        # File metadata collection
        self.db.file_metadata.create_indexes([
            IndexModel([("user_id", ASCENDING), ("path", ASCENDING)]),
            IndexModel([("category", ASCENDING)]),
            IndexModel([("last_accessed", DESCENDING)]),
            IndexModel([("user_id", ASCENDING), ("filename", ASCENDING)])
        ])
        
        # Recovery actions collection
        self.db.recovery_actions.create_indexes([
            IndexModel([("user_id", ASCENDING), ("timestamp", DESCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("action_type", ASCENDING)])
        ])
    
    def ping(self):
        """Check database connection"""
        try:
            self.client.admin.command('ping')
            return True
        except ConnectionFailure:
            return False
    
    # User operations
    def create_user(self, username: str, password_hash: str, device_id: str) -> Optional[str]:
        """Create a new user"""
        user_data = {
            "username": username,
            "password_hash": password_hash,
            "device_id": device_id,
            "created_at": datetime.utcnow(),
            "last_login": None,
            "is_active": True
        }
        
        try:
            result = self.db.users.insert_one(user_data)
            return str(result.inserted_id)
        except DuplicateKeyError:
            return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Retrieve user by username"""
        user = self.db.users.find_one({"username": username})
        if user:
            user["_id"] = str(user["_id"])
        return user
    
    def get_user_by_device_id(self, device_id: str) -> Optional[Dict]:
        """Retrieve user by device ID"""
        user = self.db.users.find_one({"device_id": device_id})
        if user:
            user["_id"] = str(user["_id"])
        return user
    
    def update_last_login(self, user_id: str):
        """Update user's last login timestamp"""
        self.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"last_login": datetime.utcnow()}}
        )
    
    # Session operations
    def create_session(self, user_id: str, token: str, device_id: str, ip_address: str, 
                      expires_in_minutes: int = 30) -> str:
        """Create a new session"""
        session_data = {
            "user_id": user_id,
            "token": token,
            "device_id": device_id,
            "ip_address": ip_address,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(minutes=expires_in_minutes),
            "last_active": datetime.utcnow(),
            "is_valid": True
        }
        
        result = self.db.sessions.insert_one(session_data)
        return str(result.inserted_id)
    
    def validate_session(self, token: str, device_id: str) -> Optional[Dict]:
        """Validate session token"""
        session = self.db.sessions.find_one({
            "token": token,
            "device_id": device_id,
            "is_valid": True,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        if session:
            # Update last active timestamp
            self.db.sessions.update_one(
                {"_id": session["_id"]},
                {"$set": {"last_active": datetime.utcnow()}}
            )
            session["_id"] = str(session["_id"])
            return session
        return None
    
    def invalidate_session(self, token: str):
        """Invalidate a session"""
        self.db.sessions.update_one(
            {"token": token},
            {"$set": {"is_valid": False}}
        )
    
    def invalidate_all_user_sessions(self, user_id: str):
        """Invalidate all sessions for a user"""
        self.db.sessions.update_many(
            {"user_id": user_id, "is_valid": True},
            {"$set": {"is_valid": False}}
        )
    
    # File metadata operations
    def store_file_metadata(self, user_id: str, filename: str, path: str, 
                           size_bytes: int, mime_type: str, category: str,
                           encrypted_key: str) -> str:
        """Store file metadata"""
        metadata = {
            "user_id": user_id,
            "filename": filename,
            "path": path,
            "size_bytes": size_bytes,
            "mime_type": mime_type,
            "category": category,
            "encrypted_key": encrypted_key,
            "created_at": datetime.utcnow(),
            "last_accessed": datetime.utcnow(),
            "access_count": 0,
            "is_available": True
        }
        
        result = self.db.file_metadata.insert_one(metadata)
        return str(result.inserted_id)
    
    def get_user_files(self, user_id: str, category: Optional[str] = None, 
                      limit: int = 100, skip: int = 0) -> List[Dict]:
        """Get files for a user, optionally filtered by category"""
        query = {"user_id": user_id, "is_available": True}
        if category:
            query["category"] = category
        
        cursor = self.db.file_metadata.find(query).sort("last_accessed", DESCENDING).skip(skip).limit(limit)
        
        files = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            files.append(doc)
        
        return files
    
    def get_file_by_id(self, file_id: str, user_id: str) -> Optional[Dict]:
        """Get specific file metadata"""
        file = self.db.file_metadata.find_one({
            "_id": ObjectId(file_id),
            "user_id": user_id,
            "is_available": True
        })
        
        if file:
            # Update access stats
            self.db.file_metadata.update_one(
                {"_id": ObjectId(file_id)},
                {
                    "$set": {"last_accessed": datetime.utcnow()},
                    "$inc": {"access_count": 1}
                }
            )
            file["_id"] = str(file["_id"])
            return file
        return None
    
    def delete_file_metadata(self, file_id: str, user_id: str) -> bool:
        """Mark file metadata as deleted"""
        result = self.db.file_metadata.update_one(
            {"_id": ObjectId(file_id), "user_id": user_id},
            {"$set": {"is_available": False}}
        )
        return result.modified_count > 0
    
    # Recovery actions operations
    def log_recovery_action(self, user_id: str, action_type: str, parameters: Dict,
                           initiated_by: str, status: str = "pending") -> str:
        """Log a recovery action"""
        action = {
            "user_id": user_id,
            "action_type": action_type,
            "parameters": parameters,
            "initiated_by": initiated_by,
            "status": status,
            "result": None,
            "timestamp": datetime.utcnow(),
            "completed_at": None,
            "requires_confirmation": True,
            "confirmed": False
        }
        
        result = self.db.recovery_actions.insert_one(action)
        return str(result.inserted_id)
    
    def update_action_status(self, action_id: str, status: str, result: Optional[Dict] = None):
        """Update action status and result"""
        update_data = {
            "status": status,
            "completed_at": datetime.utcnow() if status in ["completed", "failed"] else None
        }
        
        if result is not None:
            update_data["result"] = result
        
        self.db.recovery_actions.update_one(
            {"_id": ObjectId(action_id)},
            {"$set": update_data}
        )
    
    def confirm_action(self, action_id: str, user_id: str) -> bool:
        """Confirm a pending action"""
        result = self.db.recovery_actions.update_one(
            {"_id": ObjectId(action_id), "user_id": user_id, "requires_confirmation": True},
            {"$set": {"confirmed": True, "status": "confirmed"}}
        )
        return result.modified_count > 0
    
    def get_pending_actions(self, user_id: str, limit: int = 10) -> List[Dict]:
        """Get pending actions requiring confirmation"""
        cursor = self.db.recovery_actions.find({
            "user_id": user_id,
            "requires_confirmation": True,
            "confirmed": False,
            "status": "pending"
        }).sort("timestamp", ASCENDING).limit(limit)
        
        actions = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            actions.append(doc)
        
        return actions

# Global database instance
db = MongoDB()
