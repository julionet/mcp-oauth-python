import datetime
import secrets
import os
import jwt
from fastapi import FastAPI, HTTPException, Depends, status, Header
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATABASE_URL = "sqlite:///oauth_database.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELOS SQLALCHEMY ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    mcp_enabled = Column(Boolean, default=True)

# ──► NOVA TABELA DE DADOS DE NEGÓCIO ◄──
class UserNote(Base):
    __tablename__ = "user_notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    content = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))

class Client(Base):
    __tablename__ = "oauth_clients"
    client_id = Column(String, primary_key=True, index=True)
    scope = Column(String)

class DeviceCodeRecord(Base):
    __tablename__ = "oauth_device_codes"
    id = Column(Integer, primary_key=True, index=True)
    device_code = Column(String, unique=True, index=True)
    user_code = Column(String, unique=True, index=True)
    client_id = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    expires_at = Column(DateTime)
    is_approved = Column(Boolean, default=False)

class RefreshTokenRecord(Base):
    __tablename__ = "oauth_refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    refresh_token = Column(String, unique=True, index=True)
    client_id = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))
    expires_at = Column(DateTime)

Base.metadata.create_all(bind=engine)

def init_db():
    db = SessionLocal()
    if db.query(User).count() == 0:
        teste_user = User(username="admin", hashed_password="senha123", mcp_enabled=True)
        teste_client = Client(client_id="claude_desktop", scope="mcp:tools")
        db.add(teste_user)
        db.add(teste_client)
        db.commit()
        
        # Adiciona algumas notas de exemplo para o usuário admin (ID 1)
        nota1 = UserNote(title="Meta 2026", content="Lançar o servidor MCP seguro em produção.", user_id=1)
        nota2 = UserNote(title="Lembrete", content="Revisar chaves criptográficas RS256.", user_id=1)
        db.add(nota1)
        db.add(nota2)
        db.commit()
    db.close()

init_db()

app = FastAPI(title="Servidor OAuth 2.0 Central")

with open("private_key.pem", "r") as f:
    PRIVATE_KEY = f.read()
with open("public_key.pem", "r") as f:
    PUBLIC_KEY = f.read()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- ENDPOINTS OAUTH EXISTENTES ---

class DeviceAuthRequest(BaseModel):
    client_id: str
    scope: str

class TokenRequest(BaseModel):
    grant_type: str
    client_id: str
    device_code: str | None = None
    refresh_token: str | None = None

def gerar_par_de_tokens(db: Session, user_id: int, client_id: str):
    access_payload = {
        "sub": str(user_id),
        "client_id": client_id,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    }
    access_token = jwt.encode(access_payload, PRIVATE_KEY, algorithm="RS256")
    
    refresh_token_str = secrets.token_urlsafe(64)
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    
    db_refresh = RefreshTokenRecord(refresh_token=refresh_token_str, client_id=client_id, user_id=user_id, expires_at=expires_at)
    db.add(db_refresh)
    db.commit()
    
    return {"access_token": access_token, "token_type": "bearer", "expires_in": 900, "refresh_token": refresh_token_str}

@app.post("/oauth/device/authorize")
def device_authorize(payload: DeviceAuthRequest, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.client_id == payload.client_id).first()
    if not client: raise HTTPException(status_code=400, detail="invalid_client")
    device_code = secrets.token_urlsafe(32)
    user_code = "".join(secrets.choice("ABCDEFGHJKLMNOPQRSTUVWXYZ23456789") for _ in range(6))
    db_device = DeviceCodeRecord(device_code=device_code, user_code=user_code, client_id=payload.client_id, expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5), is_approved=False)
    db.add(db_device)
    db.commit()
    return {"device_code": device_code, "user_code": f"{user_code[:3]}-{user_code[3:]}", "verification_uri": f"http://localhost:8000/activate?code={user_code}", "expires_in": 300, "interval": 3}

@app.get("/activate")
def activate_device(code: str, db: Session = Depends(get_db)):
    clean_code = code.replace("-", "").upper()
    record = db.query(DeviceCodeRecord).filter(DeviceCodeRecord.user_code == clean_code).first()
    if not record or datetime.datetime.now(datetime.timezone.utc) > record.expires_at: return {"error": "Código inválido ou expirado."}
    usuario_banco = db.query(User).filter(User.id == 1).first()
    if not usuario_banco or not usuario_banco.mcp_enabled: return {"error": "Acesso negado."}
    record.is_approved = True
    record.user_id = usuario_banco.id
    db.commit()
    return {"message": f"Sucesso! Autorizado para {usuario_banco.username}"}

@app.post("/oauth/token")
def token_endpoint(payload: TokenRequest, db: Session = Depends(get_db)):
    now = datetime.datetime.now(datetime.timezone.utc)
    if payload.grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        record = db.query(DeviceCodeRecord).filter(DeviceCodeRecord.device_code == payload.device_code).first()
        if not record or now > record.expires_at or not record.is_approved: raise HTTPException(status_code=400, detail="invalid_grant_or_pending")
        tokens = gerar_par_de_tokens(db, record.user_id, payload.client_id)
        db.delete(record)
        db.commit()
        return tokens
    elif payload.grant_type == "refresh_token":
        record = db.query(RefreshTokenRecord).filter(RefreshTokenRecord.refresh_token == payload.refresh_token).first()
        if not record or now > record.expires_at: raise HTTPException(status_code=400, detail="invalid_grant")
        usuario = db.query(User).filter(User.id == record.user_id).first()
        if not usuario or not usuario.mcp_enabled: raise HTTPException(status_code=403, detail="disabled")
        db.delete(record)
        db.commit()
        return gerar_par_de_tokens(db, usuario.id, payload.client_id)
    raise HTTPException(status_code=400, detail="unsupported_grant_type")


# ──► NOVO ENDPOINT PROTEGIDO DE NEGÓCIO DA API CENTRAL ◄──
@app.get("/api/notes")
def get_user_notes(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente ou formato inválido")
    
    token = authorization.split(" ")[1]
    try:
        # O próprio servidor valida o JWT usando a chave pública
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        user_id = int(payload["sub"])
        
        # Busca no banco APENAS as notas que pertencem ao usuário logado
        notes = db.query(UserNote).filter(UserNote.user_id == user_id).all()
        return [{"id": n.id, "title": n.title, "content": n.content} for n in notes]
        
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
