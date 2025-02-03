from typing import Union

from fastapi import FastAPI, Query, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing_extensions import Literal
from enum import Enum
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt
from . import models
from db.database import SessionLocal

SECRET_KEY = "mysecret"
ALGORITHM = "HS256"

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Item(BaseModel):
    name: str
    price: float
    discount: Union[float, None] = None

class PetType(str, Enum):
    dog = "dog"
    cat = "cat"

class UserCreate(BaseModel):
    username: str 
    password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_in_minutes: int = 30):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not pwd_context.verify(password, user.password):
        return {"message": "These credentials incorrect"}
    return user

def create_user(db: Session, username: str, password: str):
    hashed_password = pwd_context.hash(password)
    db_user = models.User(username=username, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/register/")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = create_user(db=db, username=user.username, password=user.password)

    return user

@app.post("/login/")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}
