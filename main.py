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

class UserAccessEnum(str, Enum):
    default = "Loading..." 

class UserWithAccessEnum(str, Enum):
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
    user = db.query(models.User).filter(models.User.username == current_user).first()
    if user.role == "customer":
        new_question = models.Questions(user=current_user, question=your_question.question, status="unread", answer="No asnwer")
        db.add(new_question)
        db.commit()
        db.refresh(new_question)
        return new_question
    return {"error": "You're admin, not the user"}

@app.post("/get_questions/")
def get_all_user_questions(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == current_user).first()
    if user.role == "customer":
        all_questions = db.query(models.Questions).filter(models.Questions.user == current_user).all()
        return all_questions
    return {"error": "You're admin, not the user"}

@app.post("/ask_for_admin_access/")
def ask_for_admin_access(request_for_access: Union[bool, None], current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == current_user).first()
    if user.role == "customer":
        if request_for_access:
            user_for_access = models.Grant_Access_Users(username=current_user)
            db.add(user_for_access)
            db.commit()
            db.refresh(user_for_access)
            user = db.query(models.Grant_Access_Users).filter(models.Grant_Access_Users.username == "null").first()
            db.delete(user)
            return user_for_access
    return {"error": "You're admin, not the user"}

def get_questions(db: Session):
    return db.query(models.Questions).filter(models.Questions.status != "answered").all()

def update_question_enum(db: Session):
    questions = get_questions(db)
    question_dict = {f"{q.id}":q.question for q in questions}
    print("questions:", questions)
    
    if not questions:
        raise HTTPException(status_code=404, detail="No questions found in the database.")
    
    globals()['QuestionEnum'] = Enum('QuestionEnum', question_dict)

def get_user_for_access(db: Session):
    return db.query(models.Grant_Access_Users).all()

def update_users_access_enum(db: Session):
    users = get_user_for_access(db)
    users_dict = {f"{user.id}":user.username for user in users}
    print("users without access:", users_dict)
    
    if not users:
        user_for_access = models.Grant_Access_Users(username="null")
        db.add(user_for_access)
        db.commit()
        db.refresh(user_for_access)
    
    globals()['UserAccessEnum'] = Enum('UserAccessEnum', users_dict)

def delete_user_access(db: Session):
    return db.query(models.User).filter(models.User.role == "admin", models.User.role != "super_admin").all()

def update_users_with_access_enum(db: Session):
    users = delete_user_access(db)
    users_dict = {f"{user.id}":user.username for user in users}
    print("users:", users_dict)
    
    if not users:
        return {"message": "No users with admin role"}
    
    globals()['UserWithAccessEnum'] = Enum('UserWithAccessEnum', users_dict)

update_question_enum(SessionLocal())

update_users_access_enum(SessionLocal())

update_users_with_access_enum(SessionLocal())

#admin method

@app.post("/update_info")
async def update_info(db: Session = Depends(get_db)):
    update_question_enum(db)

@app.post("/answer_questions_protected/")
async def answer_questions(status: models.QuestionStatus, answer: str = None, question: QuestionEnum = Query(..., description="Select question"), current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == current_user).first()
    if user.role == "admin" or user.role == "super_admin":
        print(question.value)
        question_inbase = db.query(models.Questions).filter(models.Questions.question == question.value).all()
        for q in question_inbase:
            q.status = status.value 
            if answer:
                q.answer = answer
            db.commit()
            db.refresh(q)
        updated_question = db.query(models.Questions).filter(models.Questions.question == question.value).all()
        return updated_question
    return {"error": "You're user, not the admin"}


@app.post("/grant_users_access_protected/")
async def grant_users_access_protected(approve: Union[bool, None], users: UserAccessEnum = Query(..., description="Select user to grant access"), current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == current_user).first()
    
    if user.role == "super_admin":
        if approve:
            user_inbase = db.query(models.User).filter(models.User.username == users.value).first()
            user_inbase.role = "admin"
            db.commit()
            db.refresh(user_inbase)
            user = db.query(models.Grant_Access_Users).filter(models.Grant_Access_Users.username == users.value).first()
            db.delete(user)
            db.commit()
            updated_user = db.query(models.User).filter(models.User.username == users.value).first()
            
            return updated_user
        else:
            return {"message": "User was denied in the access"}
    return {"error": "You're user or admin, not the super admin"}

@app.post("/discard_users_access_protected/")
async def discard_users_access_protected(change_admin_to_user_role: Union[bool, None], users: UserWithAccessEnum = Query(..., description="Select user to discard access"), current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == current_user).first()
    
    if user.role == "super_admin":
        if change_admin_to_user_role:
            user_inbase = db.query(models.User).filter(models.User.username == users.value).first()
            user_inbase.role = "customer"
            db.commit()
            db.refresh(user_inbase)
            updated_user = db.query(models.User).filter(models.User.username == users.value).first()
            return updated_user
        else:
            return {"message": "User was left with admin access"}
    return {"error": "You're user, not the admin"}