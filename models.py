from sqlalchemy import Column, Integer, String, ForeignKey, Enum
from sqlalchemy.orm import relationship
from db.database import Base
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


