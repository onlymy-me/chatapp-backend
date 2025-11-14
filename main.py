from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import SessionLocal, User, Message
from pydantic import BaseModel
from typing import List, Dict
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# === CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://chatapp-frontend-three-sigma.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === JWT ===
SECRET_KEY = "chat-kenya-2025"
ALGORITHM = "HS256"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    username = verify_token(token)
    if not username:
        raise HTTPException(401, "Invalid token")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user

def require_admin(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user

class LoginForm(BaseModel):
    username: str
    password: str

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[WebSocket, str] = {}  # ws -> username
        self.typing_users: set = set()

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[websocket] = username

    def disconnect(self, websocket: WebSocket):
        username = self.active_connections.get(websocket)
        if username:
            self.typing_users.discard(username)
        self.active_connections.pop(websocket, None)

    async def broadcast(self, message: dict):
        for conn in self.active_connections:
            await conn.send_json(message)

    async def broadcast_online(self):
        await self.broadcast({
            "type": "online_users",
            "users": list(self.active_connections.values())
        })

    async def broadcast_typing(self):
        await self.broadcast({
            "type": "typing",
            "users": list(self.typing_users)
        })

manager = ConnectionManager()
@app.post("/register")
def register(form: LoginForm, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if user:
        raise HTTPException(400, "Username already taken")
    hashed_password = get_password_hash(form.password)
    new_user = User(username=form.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    return {"msg": "User registered successfully"}

@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    token = create_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/admin/users")
def get_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(User).all()

@app.post("/admin/users")
def create_user(
    username: str, email: str, password: str, role: str = "user",
    admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Username taken")
    hashed = get_password_hash(password)
    user = User(username=username, email=email, hashed_password=hashed, role=role)
    db.add(user)
    db.commit()
    return {"msg": "User created", "role": role}

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    db.delete(user)
    db.commit()
    return {"msg": "User deleted"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = "", db: Session = Depends(get_db)):
    username = verify_token(token)
    if not username:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, username)
    await manager.broadcast_online()

    # Send message history
    messages = db.query(Message).order_by(Message.timestamp.desc()).limit(50).all()
    await websocket.send_json({
        "type": "history",
        "messages": [{"username": m.username, "content": m.content} for m in reversed(messages)]
    })

    try:
        while True:
            data = await websocket.receive_json()
            if data["type"] == "message":
                msg = Message(username=username, content=data["content"])
                db.add(msg)
                db.commit()
                await manager.broadcast({
                    "type": "message",
                    "username": username,
                    "content": data["content"]
                })
            elif data["type"] == "typing":
                if data["is_typing"]:
                    manager.typing_users.add(username)
                else:
                    manager.typing_users.discard(username)
                await manager.broadcast_typing()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast_online()