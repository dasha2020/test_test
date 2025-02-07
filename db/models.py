from sqlalchemy import Column, Integer, String, ForeignKey, Enum
from sqlalchemy.orm import relationship
from .database import Base
from enum import Enum


class Role(str, Enum):
    customer = "customer"
    admin = "admin"


class QuestionStatus(str, Enum):
    read = "read"
    unread = "unread"
    answered = "answered"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    password = Column(String, unique=True)
    role = Column(String, default="customer")

class QuestionDB(Base):
    __tablename__ = 'questions'
    
    id = Column(Integer, primary_key=True, index=True)
    question_text = Column(String)

class Questions(Base):
    __tablename__ = 'questions_users'
    
    id = Column(Integer, primary_key=True, index=True)
    user = Column(String)
    question = Column(String)
    status = Column(String, default="unread")
    answer = Column(String, default="No answer")

class Grant_Access_Users(Base):
    __tablename__ = "access"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
