from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
import uuid
from datetime import datetime, timezone
import bcrypt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

# Models
class StudentRegister(BaseModel):
    name: str
    email: str
    password: str
    student_id: str

class StudentLogin(BaseModel):
    email: str
    password: str

class Student(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    email: str
    student_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

@api_router.post("/register")
async def register_student(student: StudentRegister):
    existing = await db.students.find_one({"email": student.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pw = bcrypt.hashpw(student.password.encode('utf-8'), bcrypt.gensalt())
    student_data = {
        "id": str(uuid.uuid4()),
        "name": student.name,
        "email": student.email,
        "password": hashed_pw.decode('utf-8'),
        "student_id": student.student_id,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.students.insert_one(student_data)
    return {"message": "Registration successful", "student_id": student_data["id"]}

@api_router.post("/login")
async def login_student(login: StudentLogin):
    student = await db.students.find_one({"email": login.email})
    if not student:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not bcrypt.checkpw(login.password.encode('utf-8'), student["password"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {"message": "Login successful", "student_id": student["id"], "name": student["name"]}

@api_router.get("/student/{student_id}")
async def get_student(student_id: str):
    student = await db.students.find_one({"id": student_id}, {"_id": 0, "password": 0})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    return student

app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
