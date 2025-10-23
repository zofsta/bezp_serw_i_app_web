from fastapi import FastAPI, Form, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, validator, Field
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

# ═══════════════════════════════════════════════════════════
# WALIDACJA - MODELE PYDANTIC
# ═══════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    """Model walidacyjny dla rejestracji"""
    username: str = Field(..., min_length=3, max_length=20)
    password: str = Field(..., min_length=8, max_length=100)
    email: str = Field(..., min_length=5, max_length=100)

    @validator('username')
    def username_must_be_alphanumeric(cls, v):
        """Username może zawierać tylko litery, cyfry i podkreślenia"""
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username może zawierać tylko litery, cyfry i podkreślenia')
        return v.lower()  # Normalizacja do małych liter

    @validator('username')
    def username_must_not_start_with_number(cls, v):
        """Username nie może zaczynać się od cyfry"""
        if v[0].isdigit():
            raise ValueError('Username nie może zaczynać się od cyfry')
        return v

    @validator('password')
    def password_must_be_strong(cls, v):
        """
        Hasło musi zawierać:
        - Minimum 8 znaków
        - Przynajmniej jedną wielką literę
        - Przynajmniej jedną małą literę
        - Przynajmniej jedną cyfrę
        - Przynajmniej jeden znak specjalny
        """
        if not re.search(r'[A-Z]', v):
            raise ValueError('Hasło musi zawierać przynajmniej jedną wielką literę')
        if not re.search(r'[a-z]', v):
            raise ValueError('Hasło musi zawierać przynajmniej jedną małą literę')
        if not re.search(r'\d', v):
            raise ValueError('Hasło musi zawierać przynajmniej jedną cyfrę')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Hasło musi zawierać przynajmniej jeden znak specjalny')
        return v

    @validator('email')
    def email_must_be_valid(cls, v):
        """Walidacja formatu email"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, v):
            raise ValueError('Nieprawidłowy format adresu email')
        return v.lower()


class LoginRequest(BaseModel):
    """Model walidacyjny dla logowania"""
    username: str = Field(..., min_length=3, max_length=20)
    password: str = Field(..., min_length=1, max_length=100)


class PostRequest(BaseModel):
    """Model walidacyjny dla tworzenia postów"""
    title: str = Field(..., min_length=5, max_length=100)
    content: str = Field(..., min_length=10, max_length=5000)

    @validator('title')
    def title_must_not_be_empty(cls, v):
        """Tytuł nie może zawierać tylko spacji"""
        if not v.strip():
            raise ValueError('Tytuł nie może być pusty')
        return v.strip()

    @validator('content')
    def content_must_not_be_empty(cls, v):
        """Treść nie może zawierać tylko spacji"""
        if not v.strip():
            raise ValueError('Treść nie może być pusta')
        return v.strip()


# ═══════════════════════════════════════════════════════════
# FUNKCJE POMOCNICZE DO WALIDACJI
# ═══════════════════════════════════════════════════════════

def validate_registration_data(username: str, password: str, email: str):
    """
    Waliduje dane rejestracji i zwraca błędy
    Returns: (is_valid: bool, errors: list)
    """
    try:
        RegisterRequest(username=username, password=password, email=email)
        return True, []
    except Exception as e:
        errors = []
        if hasattr(e, 'errors'):
            for error in e.errors():
                field = error['loc'][0]
                msg = error['msg']
                errors.append(f"{field}: {msg}")
        else:
            errors.append(str(e))
        return False, errors


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

# Get current user from session
def get_current_user(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# ═══════════════════════════════════════════════════════════
# ENDPOINTY Z WALIDACJĄ
# ═══════════════════════════════════════════════════════════

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
    """
    REJESTRACJA Z PEŁNĄ WALIDACJĄ

    Waliduje:
    1. Długość username (3-20 znaków)
    2. Format username (tylko litery, cyfry, _)
    3. Username nie zaczyna się od cyfry
    4. Długość hasła (minimum 8 znaków)
    5. Siła hasła (wielka/mała litera, cyfra, znak specjalny)
    6. Format email
    7. Unikalność username i email w bazie
    """

    # Walidacja formatów i wymagań
    try:
        validated_data = RegisterRequest(
            username=username,
            password=password,
            email=email
        )
    except Exception as e:
        error_messages = []
        if hasattr(e, 'errors'):
            for error in e.errors():
                error_messages.append(error['msg'])
        raise HTTPException(
            status_code=422,
            detail={"message": "Validation errors", "errors": error_messages}
        )

    # Sprawdzenie unikalności username
    existing_user = db.query(User).filter(
        User.username == validated_data.username
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="This username is already taken"
        )

    # Sprawdzenie unikalności email
    existing_email = db.query(User).filter(
        User.email == validated_data.email
    ).first()
    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="This email address is already taken"
        )

    # KROK 4: Tworzenie użytkownika
    hashed_password = pwd_context.hash(validated_data.password)
    new_user = User(
        username=validated_data.username,
        hashed_password=hashed_password,
        email=validated_data.email
    )
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
    """
    LOGOWANIE Z WALIDACJĄ

    Waliduje:
    1. Obecność obu pól
    2. Podstawowa długość
    3. Istnienie użytkownika
    4. Poprawność hasła
    """

    # Walidacja formatu
    try:
        validated_data = LoginRequest(username=username, password=password)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail="Wrong logging credentials"
        )

    # Sprawdzenie użytkownika
    user = db.query(User).filter(
        User.username == validated_data.username.lower()
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Wrong username or password"
        )

    # Weryfikacja hasła
    if not pwd_context.verify(validated_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Wrong username or password"
        )

    # Tworzenie sesji
    request.session["user_id"] = user.id
    request.session["username"] = user.username

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
    """
    TWORZENIE POSTA Z WALIDACJĄ

    Waliduje:
    1. Długość tytułu (5-100 znaków)
    2. Długość treści (10-5000 znaków)
    3. Tytuł i treść nie są puste (same spacje)
    """

    # Walidacja danych
    try:
        validated_data = PostRequest(title=title, content=content)
    except Exception as e:
        error_messages = []
        if hasattr(e, 'errors'):
            for error in e.errors():
                error_messages.append(error['msg'])
        raise HTTPException(
            status_code=422,
            detail={"message": "Post'validation errors", "errors": error_messages}
        )

    # Tworzenie posta
    new_post = Post(
        title=validated_data.title,
        content=validated_data.content,
        user_id=current_user.id
    )
    db.add(new_post)
    db.commit()

    return RedirectResponse(url="/main", status_code=303)
