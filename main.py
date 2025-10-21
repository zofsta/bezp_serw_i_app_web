from fastapi import FastAPI, Form, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
import os
import time
import re

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
    user_id = Column(Integer, ForeignKey("users.id"))

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

# Add session middleware
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production-min-32-chars")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Inpute data sanitization
def sanitize_input(text: str) -> str:
    # HTML tags sanitizatiom
    return re.sub(r'[<>"]', "", text)

def validate_username(username: str) -> bool:
    # Username validation (letters, numbers, _ , 3 to 30 characters)
    return re.match(r'^[A-Za-z0-9_]{3,30}$', username) is not None

def validate_email(email: str) -> bool:
    # Email valdation
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email) is not None

# Get current user from session
def get_current_user(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

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
    # Sanitization and Walidation
    if not validate_username(username):
        raise HTTPException(status_code=400, detail="Username must be 3-30 chars, letters/numbers/_ only")
    username = sanitize_input(username)

    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    email = sanitize_input(email)

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
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Sanitization and Walidation
    username = sanitize_input(username)

    user = db.query(User).filter(User.username == username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Save user_id in session
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    
    print(f"User logged in: {user.username}, ID: {user.id}")  # DEBUG
    print(f"Session content: {request.session}")  # DEBUG

    return RedirectResponse(url="/main", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

@app.get("/main", response_class=HTMLResponse)
async def main_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    posts = db.query(Post).all()
    return templates.TemplateResponse(
        "main.html",
        {
            "request": request,
            "posts": posts,
            "username": current_user.username
        }
    )

@app.get("/create", response_class=HTMLResponse)
async def create_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    return templates.TemplateResponse(
        "create.html",
        {
            "request": request,
            "username": current_user.username
        }
    )

@app.post("/create")
async def create(
    title: str = Form(...),
    content: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Sanitization of content and title of the post
    clean_title = sanitize_input(title)
    clean_content = sanitize_input(content)

    new_post = Post(title=clean_title, content=clean_content, user_id=current_user.id)
    db.add(new_post)
    db.commit()

    return RedirectResponse(url="/main", status_code=303)

