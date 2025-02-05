from typing import Union

from fastapi import FastAPI, Query, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing_extensions import Literal
from enum import Enum
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt
from db import models
from db.database import SessionLocal, engine, Base
from jose import JWTError
from typing import List
from sqlalchemy import create_engine, Column, Integer, String

SECRET_KEY = "mysecret"
ALGORITHM = "HS256"

Base.metadata.create_all(bind=engine)
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



class UserCreate(BaseModel):
    username: str 
    password: str

class QuestionEnum(str, Enum):
    default = "Loading..." 

class QuestionCreate(BaseModel):
    question: str 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_in_minutes: int = 30):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate(username: str, password: str, db: Session):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not pwd_context.verify(password, user.password):
        return {"message": "These credentials incorrect"}
    return user

def create_user(username: str, password: str, db: Session):
    hashed_password = pwd_context.hash(password)
    db_user = models.User(username=username, password=hashed_password, role="customer")
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    if username is None:
        raise credentials_exception
    return username

@app.post("/register/")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = create_user(username=user.username, password=user.password, db=db)

    return user

@app.post("/login/")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate(form_data.username, form_data.password, db=db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/ask_question/")
def ask_question(your_question: QuestionCreate, current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    new_question = models.Questions(user=current_user, question=your_question.question, status="unread", answer="No asnwer")
    db.add(new_question)
    db.commit()
    db.refresh(new_question)
    return new_question

@app.post("/get_questions/")
def get_questions(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    all_questions = db.query(models.Questions).filter(models.Questions.user == current_user).all()
    return all_questions


def get_questions(db: Session):
    return db.query(models.Questions).all()

def update_question_enum(db: Session):
    questions = get_questions(db)
    question_dict = {f"{q.id}":q.question for q in questions}
    print("questions:", questions)
    
    if not questions:
        raise HTTPException(status_code=404, detail="No questions found in the database.")
    
    globals()['QuestionEnum'] = Enum('QuestionEnum', question_dict)


def populate_questions(db: Session):
    questions = ["What is your name?", "How old are you?", "Where are you from?"]
    for q in questions:
        if not db.query(models.Questions).filter(models.Questions.question == q).first():
            db.add(models.Questions(question=q))
    db.commit()

update_question_enum(SessionLocal())

#admin method
@app.post("/create-item")
async def create_item(question: QuestionEnum = Query(..., description="Select a question")):
    return {"selected_question": question}