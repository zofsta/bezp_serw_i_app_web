from fastapi import FastAPI, Form, HTTPException, Depends, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, validator, Field
from datetime import datetime
import os
import time
import re
import uuid
import shutil
from pathlib import Path

# Database setup - REQUIRE environment variable, no localhost fallback
DATABASE_URL = (
    os.getenv("DATABASE_URL") or
    os.getenv("POSTGRESQLCONNSTR_DEFAULTCONNECTION")
)

# Validate that DATABASE_URL is set BEFORE creating engine
if not DATABASE_URL:
    import sys
    sys.exit(1)

print(f"✓ DATABASE_URL found: {DATABASE_URL[:30]}...") # Show first 30 chars for verification

# Database setup - REQUIRE environment variable, no localhost fallback
DATABASE_URL = (
    os.getenv("DATABASE_URL") or
    os.getenv("POSTGRESQLCONNSTR_DEFAULTCONNECTION")
)

# Validate that DATABASE_URL is set BEFORE creating engine
if not DATABASE_URL:
    import sys
    sys.exit(1)

print(f"✓ DATABASE_URL found: {DATABASE_URL[:30]}...") # Show first 30 chars for verification

# Detect database type (SQLite vs PostgreSQL)
is_sqlite = DATABASE_URL.startswith('sqlite')

# Create engine with appropriate settings based on database type
if is_sqlite:
    # SQLite configuration (for testing and local development)
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
    print("✓ Using SQLite database (test mode)")
else:
    # PostgreSQL configuration (for production on Azure)
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,  # Verify connections before using them
        pool_size=10,
        max_overflow=20,
        pool_recycle=3600,  # Recycle connections after 1 hour
        connect_args={
            "connect_timeout": 10,
            "options": "-c timezone=utc"
        }
    )
    print("✓ Using PostgreSQL database (production mode)")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database connection status
db_connected = False

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True)
    is_admin = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

class PostTag(Base):
    __tablename__ = "post_tags"
    post_id = Column(Integer, ForeignKey("posts.id", ondelete="CASCADE"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    content = Column(Text)
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    author = relationship("User", foreign_keys=[user_id])
    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")
    tags = relationship("Tag", secondary="post_tags", backref="posts")
    reactions = relationship("PostReaction", back_populates="post", cascade="all, delete-orphan")
    attachments = relationship("PostAttachment", back_populates="post", cascade="all, delete-orphan")
    content_blocks = relationship("ContentBlock", back_populates="post", cascade="all, delete-orphan", order_by="ContentBlock.order_index")

    @property
    def author_username(self):
        return self.author.username if self.author else "Unknown"

class PostAttachment(Base):
    __tablename__ = "post_attachments"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id", ondelete="CASCADE"))
    filename = Column(String(255), nullable=False)
    filepath = Column(String(500), nullable=False)
    filetype = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)

    post = relationship("Post", back_populates="attachments")

class ContentBlock(Base):
    __tablename__ = "content_blocks"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id", ondelete="CASCADE"))
    block_type = Column(String(20), nullable=False)
    content = Column(Text)
    url = Column(String(500))
    order_index = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    post = relationship("Post", back_populates="content_blocks")

class PostReaction(Base):
    __tablename__ = "post_reactions"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id", ondelete="CASCADE"))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    reaction_type = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)

    post = relationship("Post", back_populates="reactions")
    user = relationship("User")

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    post_id = Column(Integer, ForeignKey("posts.id", ondelete="CASCADE"))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    created_at = Column(DateTime, default=datetime.utcnow)

    post = relationship("Post", back_populates="comments")
    author = relationship("User")
    reactions = relationship("CommentReaction", back_populates="comment", cascade="all, delete-orphan")

    @property
    def author_username(self):
        return self.author.username if self.author else "Unknown"

class CommentReaction(Base):
    __tablename__ = "comment_reactions"
    id = Column(Integer, primary_key=True, index=True)
    comment_id = Column(Integer, ForeignKey("comments.id", ondelete="CASCADE"))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    reaction_type = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)

    comment = relationship("Comment", back_populates="reactions")
    user = relationship("User")

class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)

class ThreadTag(Base):
    __tablename__ = "thread_tags"
    thread_id = Column(Integer, ForeignKey("threads.id", ondelete="CASCADE"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)

class Thread(Base):
    __tablename__ = "threads"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    created_at = Column(DateTime, default=datetime.utcnow)

    creator = relationship("User", foreign_keys=[user_id])
    messages = relationship("ThreadMessage", back_populates="thread", cascade="all, delete-orphan")
    attachments = relationship("ThreadAttachment", back_populates="thread", cascade="all, delete-orphan")
    tags = relationship("Tag", secondary="thread_tags", backref="threads")

    @property
    def creator_username(self):
        return self.creator.username if self.creator else "Unknown"

class ThreadMessage(Base):
    __tablename__ = "thread_messages"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    thread_id = Column(Integer, ForeignKey("threads.id", ondelete="CASCADE"))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    created_at = Column(DateTime, default=datetime.utcnow)

    thread = relationship("Thread", back_populates="messages")
    author = relationship("User")

    @property
    def author_username(self):
        return self.author.username if self.author else "Unknown"

class ThreadAttachment(Base):
    __tablename__ = "thread_attachments"
    id = Column(Integer, primary_key=True, index=True)
    thread_id = Column(Integer, ForeignKey("threads.id", ondelete="CASCADE"))
    filename = Column(String(255), nullable=False)
    filepath = Column(String(500), nullable=False)
    filetype = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)

    thread = relationship("Thread", back_populates="attachments")

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


def initialize_database():
    """
    Try to connect to the database and create tables.
    Returns True if successful, False otherwise.
    """
    global db_connected
    max_retries = 5
    print(f"\n🔄 Attempting to connect to database...")
    
    # Detect database type
    is_sqlite = DATABASE_URL.startswith('sqlite')
    
    if not is_sqlite:
        print(f"📍 Server: {DATABASE_URL.split('@')[1].split('/')[0] if '@' in DATABASE_URL else 'unknown'}")
    
    for i in range(max_retries):
        try:
            # Test connection with appropriate query based on database type
            from sqlalchemy import text
            with engine.connect() as conn:
                if is_sqlite:
                    # SQLite - test with simple query
                    result = conn.execute(text("SELECT sqlite_version()"))
                    version = result.fetchone()[0]
                    print(f"✓ Database connected successfully!")
                    print(f"✓ SQLite version: {version}")
                else:
                    # PostgreSQL - use version() function
                    result = conn.execute(text("SELECT version()"))
                    version = result.fetchone()[0]
                    print(f"✓ Database connected successfully!")
                    print(f"✓ PostgreSQL version: {version.split(',')[0]}")
            
            # Create tables if connection successful
            Base.metadata.create_all(bind=engine)
            db_connected = True
            print("✓ Database tables initialized")
            return True
            
        except Exception as e:
            if i < max_retries - 1:
                print(f"⚠ Database connection attempt {i+1}/{max_retries} failed")
                print(f"   Error: {str(e)[:100]}")
                time.sleep(2)
            else:
                print(f"\n{'='*80}")
                print(f"✗ CRITICAL: Failed to connect to database after {max_retries} attempts")
                print(f"✗ Error: {str(e)}")
                print(f"{'='*80}")
                if not is_sqlite:
                    print("Possible issues:")
                    print("1. DATABASE_URL is incorrectly formatted")
                    print("2. PostgreSQL server firewall blocks Azure App Service")
                    print("3. Wrong credentials (username/password)")
                    print("4. Database does not exist")
                    print(f"{'='*80}\n")
                db_connected = False
                raise ConnectionError(f"Cannot connect to database: {str(e)}")
    
    return False

# Initialize database on module load
initialize_database()

app = FastAPI()

# Add session middleware
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production-min-32-chars")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup uploads directory
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

templates = Jinja2Templates(directory="templates")

# Add Jinja2 filter for JSON parsing
import json as json_module
def from_json_filter(value):
    if not value:
        return []
    try:
        return json_module.loads(value)
    except:
        return []

templates.env.filters['from_json'] = from_json_filter

# Create admin user on startup
@app.on_event("startup")
async def create_admin_user():
    """Create admin user if database is available"""
    if not db_connected:
        print("⚠ Skipping admin user creation - database not connected")
        return

    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            # Password: Admin@123 (meets all requirements: 8+ chars, uppercase, lowercase, digit, special char)
            hashed_password = pwd_context.hash("Admin@123")
            admin = User(
                username="admin",
                hashed_password=hashed_password,
                email="admin@admin.com",
                is_admin=1
            )
            db.add(admin)
            db.commit()
            print("✓ Admin user created successfully with username: admin, password: Admin@123")
        else:
            print("✓ Admin user already exists")
    except Exception as e:
        print(f"✗ Error creating admin user: {e}")
        db.rollback()
    finally:
        db.close()

# Dependency
def get_db():
    """
    Database session dependency with connection check.
    Raises HTTPException if database is not connected.
    """
    if not db_connected:
        raise HTTPException(
            status_code=503,
            detail="Database is currently unavailable. Please try again later."
        )
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

@app.get("/health")
async def health_check():
    """Health check endpoint for Azure Web Services"""
    return {
        "status": "healthy" if db_connected else "degraded",
        "database": "connected" if db_connected else "disconnected",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("register.html", {
        "request": request,
        "db_connected": db_connected
    })


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {
        "request": request,
        "db_connected": db_connected
    })


@app.post("/register")
async def register(
    request: Request,
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
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": " | ".join(error_messages),
                "username": username,
                "email": email
            }
        )

    # Sprawdzenie unikalności username
    existing_user = db.query(User).filter(
        User.username == validated_data.username
    ).first()
    if existing_user:
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "This username is already taken",
                "username": username,
                "email": email
            }
        )

    # Sprawdzenie unikalności email
    existing_email = db.query(User).filter(
        User.email == validated_data.email
    ).first()
    if existing_email:
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "This email address is already taken",
                "username": username,
                "email": email
            }
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
    return templates.TemplateResponse("login.html", {
        "request": request,
        "db_connected": db_connected
    })


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
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Invalid credentials format",
                "username": username
            }
        )

    # Sprawdzenie użytkownika
    user = db.query(User).filter(
        User.username == validated_data.username.lower()
    ).first()

    if not user:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Wrong username or password",
                "username": username
            }
        )

    # Weryfikacja hasła
    if not pwd_context.verify(validated_data.password, user.hashed_password):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Wrong username or password",
                "username": username
            }
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
    tag: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    all_tags = db.query(Tag).all()
    query = db.query(Post).order_by(Post.created_at.desc())

    if tag:
        query = query.join(Post.tags).filter(Tag.name == tag)

    posts = query.all()
    return templates.TemplateResponse(
        "main.html",
        {
            "request": request,
            "posts": posts,
            "username": current_user.username,
            "all_tags": all_tags,
            "selected_tag": tag,
            "is_admin": current_user.is_admin == 1
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
    tags: str = Form(""),
    blocks: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    import json as json_lib

    new_post = Post(
        title=title,
        content="",
        user_id=current_user.id
    )
    db.add(new_post)
    db.flush()

    # Handle tags
    if tags:
        tag_names = [tag.strip().lower() for tag in tags.split(',') if tag.strip()]
        for tag_name in tag_names[:5]:
            tag = db.query(Tag).filter(Tag.name == tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.add(tag)
                db.flush()
            post_tag = PostTag(post_id=new_post.id, tag_id=tag.id)
            db.add(post_tag)

    # Handle content blocks
    try:
        blocks_data = json_lib.loads(blocks)
        for idx, block in enumerate(blocks_data):
            block_type = block.get('type')
            if block_type == 'text':
                content_block = ContentBlock(
                    post_id=new_post.id,
                    block_type='text',
                    content=block.get('content'),
                    order_index=idx
                )
                db.add(content_block)
            elif block_type in ['image', 'video']:
                content_block = ContentBlock(
                    post_id=new_post.id,
                    block_type=block_type,
                    url=block.get('url'),
                    order_index=idx
                )
                db.add(content_block)
    except Exception as e:
        db.rollback()
        return RedirectResponse(url="/create?error=Failed to save content blocks", status_code=303)

    db.commit()
    return RedirectResponse(url="/main", status_code=303)


# ═══════════════════════════════════════════════════════════
# IMAGE UPLOAD & REACTIONS
# ═══════════════════════════════════════════════════════════

@app.post("/upload-image")
async def upload_image(
    image: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    if not image.content_type or not image.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    file_ext = Path(image.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    file_path = UPLOAD_DIR / unique_filename
    try:
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    return JSONResponse({
        "success": True,
        "url": f"/uploads/{unique_filename}"
    })

@app.post("/upload-video")
async def upload_video(
    video: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    if not video.content_type or not video.content_type.startswith('video/'):
        raise HTTPException(status_code=400, detail="File must be a video")
    file_ext = Path(video.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    file_path = UPLOAD_DIR / unique_filename
    try:
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(video.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    return JSONResponse({
        "success": True,
        "url": f"/uploads/{unique_filename}"
    })

@app.post("/post/{post_id}/react")
async def react_to_post(
    post_id: int,
    reaction_type: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    if reaction_type not in ['upvote', 'downvote']:
        raise HTTPException(status_code=400, detail="Invalid reaction type")

    existing_reaction = db.query(PostReaction).filter(
        PostReaction.post_id == post_id,
        PostReaction.user_id == current_user.id
    ).first()

    if existing_reaction:
        if existing_reaction.reaction_type == reaction_type:
            db.delete(existing_reaction)
            db.commit()
            return JSONResponse({"status": "success", "action": "removed"})
        else:
            existing_reaction.reaction_type = reaction_type
            db.commit()
            return JSONResponse({"status": "success", "action": "changed"})
    else:
        new_reaction = PostReaction(
            post_id=post_id,
            user_id=current_user.id,
            reaction_type=reaction_type
        )
        db.add(new_reaction)
        db.commit()
        return JSONResponse({"status": "success", "action": "added"})

@app.post("/post/{post_id}/comment")
async def add_comment(
    post_id: int,
    content: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not content or len(content.strip()) < 1:
        raise HTTPException(status_code=400, detail="Comment cannot be empty")
    if len(content) > 1000:
        raise HTTPException(status_code=400, detail="Comment too long (max 1000 characters)")
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    new_comment = Comment(
        content=content.strip(),
        post_id=post_id,
        user_id=current_user.id
    )
    db.add(new_comment)
    db.commit()
    return JSONResponse({"status": "success", "comment_id": new_comment.id})

@app.post("/comment/{comment_id}/react")
async def react_to_comment(
    comment_id: int,
    reaction_type: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    if reaction_type not in ['upvote', 'downvote']:
        raise HTTPException(status_code=400, detail="Invalid reaction type")

    existing_reaction = db.query(CommentReaction).filter(
        CommentReaction.comment_id == comment_id,
        CommentReaction.user_id == current_user.id
    ).first()

    if existing_reaction:
        if existing_reaction.reaction_type == reaction_type:
            db.delete(existing_reaction)
            db.commit()
            return JSONResponse({"status": "success", "action": "removed"})
        else:
            existing_reaction.reaction_type = reaction_type
            db.commit()
            return JSONResponse({"status": "success", "action": "changed"})
    else:
        new_reaction = CommentReaction(
            comment_id=comment_id,
            user_id=current_user.id,
            reaction_type=reaction_type
        )
        db.add(new_reaction)
        db.commit()
        return JSONResponse({"status": "success", "action": "added"})

@app.delete("/admin/delete-post/{post_id}")
async def admin_delete_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.is_admin != 1:
        raise HTTPException(status_code=403, detail="Admin access required")
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    db.delete(post)
    db.commit()
    return JSONResponse({"status": "success", "message": "Post deleted"})

@app.delete("/admin/delete-comment/{comment_id}")
async def admin_delete_comment(
    comment_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.is_admin != 1:
        raise HTTPException(status_code=403, detail="Admin access required")
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    db.delete(comment)
    db.commit()
    return JSONResponse({"status": "success", "message": "Comment deleted"})


# ═══════════════════════════════════════════════════════════
# THREADS ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.get("/threads", response_class=HTMLResponse)
async def threads_page(
    request: Request,
    tag: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    all_tags = db.query(Tag).all()
    query = db.query(Thread).order_by(Thread.created_at.desc())
    if tag:
        query = query.join(Thread.tags).filter(Tag.name == tag)
    threads = query.all()
    return templates.TemplateResponse(
        "threads.html",
        {
            "request": request,
            "threads": threads,
            "username": current_user.username,
            "all_tags": all_tags,
            "selected_tag": tag,
            "is_admin": current_user.is_admin == 1
        }
    )

@app.post("/create-thread")
async def create_thread(
    request: Request,
    title: str = Form(...),
    tags: str = Form(""),
    attachment: UploadFile = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not title or len(title.strip()) < 3:
        return RedirectResponse(url="/threads?error=Title too short", status_code=303)
    if len(title) > 200:
        return RedirectResponse(url="/threads?error=Title too long", status_code=303)

    new_thread = Thread(title=title.strip(), user_id=current_user.id)
    db.add(new_thread)
    db.flush()

    if tags:
        tag_names = [tag.strip().lower() for tag in tags.split(',') if tag.strip()]
        for tag_name in tag_names[:5]:
            tag = db.query(Tag).filter(Tag.name == tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.add(tag)
                db.flush()
            thread_tag = ThreadTag(thread_id=new_thread.id, tag_id=tag.id)
            db.add(thread_tag)

    if attachment and attachment.filename:
        allowed_image_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
        allowed_video_types = ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime']
        if attachment.content_type not in allowed_image_types + allowed_video_types:
            db.rollback()
            return RedirectResponse(url="/threads?error=Invalid file type", status_code=303)
        contents = await attachment.read()
        if len(contents) > 10 * 1024 * 1024:
            db.rollback()
            return RedirectResponse(url="/threads?error=File too large", status_code=303)
        file_ext = Path(attachment.filename).suffix
        unique_filename = f"{uuid.uuid4()}{file_ext}"
        file_path = UPLOAD_DIR / unique_filename
        try:
            with file_path.open("wb") as buffer:
                buffer.write(contents)
            filetype = 'image' if attachment.content_type in allowed_image_types else 'video'
            thread_attachment = ThreadAttachment(
                thread_id=new_thread.id,
                filename=attachment.filename,
                filepath=f"uploads/{unique_filename}",
                filetype=filetype
            )
            db.add(thread_attachment)
        except Exception as e:
            db.rollback()
            return RedirectResponse(url="/threads?error=Failed to save file", status_code=303)

    db.commit()
    return RedirectResponse(url=f"/thread/{new_thread.id}", status_code=303)

@app.get("/thread/{thread_id}", response_class=HTMLResponse)
async def thread_detail(
    request: Request,
    thread_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    thread = db.query(Thread).filter(Thread.id == thread_id).first()
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")
    messages = db.query(ThreadMessage).filter(
        ThreadMessage.thread_id == thread_id
    ).order_by(ThreadMessage.created_at.asc()).all()
    return templates.TemplateResponse(
        "thread_detail.html",
        {
            "request": request,
            "thread": thread,
            "messages": messages,
            "username": current_user.username
        }
    )

@app.post("/thread/{thread_id}/message")
async def add_thread_message(
    thread_id: int,
    content: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not content or len(content.strip()) < 1:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    if len(content) > 1000:
        raise HTTPException(status_code=400, detail="Message too long")
    thread = db.query(Thread).filter(Thread.id == thread_id).first()
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")
    new_message = ThreadMessage(
        content=content.strip(),
        thread_id=thread_id,
        user_id=current_user.id
    )
    db.add(new_message)
    db.commit()
    return RedirectResponse(url=f"/thread/{thread_id}", status_code=303)

@app.delete("/admin/delete-thread/{thread_id}")
async def admin_delete_thread(
    thread_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.is_admin != 1:
        raise HTTPException(status_code=403, detail="Admin access required")
    thread = db.query(Thread).filter(Thread.id == thread_id).first()
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")
    for attachment in thread.attachments:
        try:
            file_path = Path(attachment.filepath)
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            print(f"Failed to delete file {attachment.filepath}: {e}")
    db.delete(thread)
    db.commit()
    return JSONResponse({"status": "success", "message": "Thread deleted"})
