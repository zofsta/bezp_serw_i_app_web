from fastapi import FastAPI, Form, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import os
import time

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/authdb")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True)

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    content = Column(String)

# Wait for database and create tables
max_retries = 30
for i in range(max_retries):
    try:
        Base.metadata.create_all(bind=engine)
        break
    except Exception as e:
        if i < max_retries - 1:
            time.sleep(1)
        else:
            raise

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register(
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if user exists
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Create new user
    hashed_password = pwd_context.hash(password)
    new_user = User(username=username, hashed_password=hashed_password, email=email)
    db.add(new_user)
    db.commit()

    return RedirectResponse(url="/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Find user
    user = db.query(User).filter(User.username == username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return RedirectResponse(url="/main", status_code=303)

@app.get("/main", response_class=HTMLResponse)
async def main_page(request: Request, db: Session = Depends(get_db)):

    posts = db.query(Post).all()
    return templates.TemplateResponse("main.html", {"request": request, "posts": posts})

@app.get("/create", response_class=HTMLResponse)
async def create_page(request: Request):
    return templates.TemplateResponse("create.html", {"request": request})

@app.post("/create")
async def create(
    title: str = Form(...),
    content: str = Form(...),
    db: Session = Depends(get_db)
):


    new_post = Post(title=title, content=content)
    db.add(new_post)
    db.commit()

    return RedirectResponse(url="/main", status_code=303)