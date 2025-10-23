from fastapi import FastAPI, Form, HTTPException, Depends, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import shutil
from pathlib import Path
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Table, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime
import json
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

# Association table for many-to-many relationship between posts and tags
post_tags = Table(
    'post_tags',
    Base.metadata,
    Column('post_id', Integer, ForeignKey('posts.id'), primary_key=True),
    Column('tag_id', Integer, ForeignKey('tags.id'), primary_key=True)
)

# Association table for many-to-many relationship between threads and tags
thread_tags = Table(
    'thread_tags',
    Base.metadata,
    Column('thread_id', Integer, ForeignKey('threads.id'), primary_key=True),
    Column('tag_id', Integer, ForeignKey('tags.id'), primary_key=True)
)

# User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True)
    is_admin = Column(Boolean, default=False)

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    content = Column(String)  # Legacy field for simple posts
    content_blocks = Column(Text)  # JSON array of {type: 'text'|'image', content: '...'} for nested posts
    author_username = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    tags = relationship("Tag", secondary=post_tags, back_populates="posts")
    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")
    reactions = relationship("PostReaction", back_populates="post", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="post", cascade="all, delete-orphan")

class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    posts = relationship("Post", secondary=post_tags, back_populates="tags")
    threads = relationship("Thread", secondary=thread_tags, back_populates="tags")

class Thread(Base):
    __tablename__ = "threads"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    creator_username = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    tags = relationship("Tag", secondary=thread_tags, back_populates="threads")
    messages = relationship("Message", back_populates="thread", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="thread", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    author_username = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    thread_id = Column(Integer, ForeignKey("threads.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    thread = relationship("Thread", back_populates="messages")

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    author_username = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    post_id = Column(Integer, ForeignKey("posts.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    post = relationship("Post", back_populates="comments")
    reactions = relationship("CommentReaction", back_populates="comment", cascade="all, delete-orphan")

class PostReaction(Base):
    __tablename__ = "post_reactions"
    id = Column(Integer, primary_key=True, index=True)
    reaction_type = Column(String)  # 'upvote' or 'downvote'
    post_id = Column(Integer, ForeignKey("posts.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    post = relationship("Post", back_populates="reactions")

class CommentReaction(Base):
    __tablename__ = "comment_reactions"
    id = Column(Integer, primary_key=True, index=True)
    reaction_type = Column(String)  # 'upvote' or 'downvote'
    comment_id = Column(Integer, ForeignKey("comments.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    comment = relationship("Comment", back_populates="reactions")

class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    filepath = Column(String)
    filetype = Column(String)  # 'image' or 'video' or 'other'
    filesize = Column(Integer)  # in bytes
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=True)
    thread_id = Column(Integer, ForeignKey("threads.id"), nullable=True)
    post = relationship("Post", back_populates="attachments")
    thread = relationship("Thread", back_populates="attachments")

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

# Create admin user if it doesn't exist
def create_admin_user():
    db = SessionLocal()
    try:
        admin_username = os.getenv("ADMIN_USERNAME", "admin")
        admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
        admin_email = os.getenv("ADMIN_EMAIL", "admin@forum.local")

        # Check if admin user already exists
        existing_admin = db.query(User).filter(User.username == admin_username).first()
        if not existing_admin:
            hashed_password = pwd_context.hash(admin_password)
            admin_user = User(
                username=admin_username,
                hashed_password=hashed_password,
                email=admin_email,
                is_admin=True
            )
            db.add(admin_user)
            db.commit()
            print(f"Admin user created: {admin_username}")
        else:
            # Ensure existing user has admin privileges
            if not existing_admin.is_admin:
                existing_admin.is_admin = True
                db.commit()
                print(f"Admin privileges granted to: {admin_username}")
    except Exception as e:
        print(f"Error creating admin user: {e}")
        db.rollback()
    finally:
        db.close()

create_admin_user()

app = FastAPI()

# Add session middleware
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production-min-32-chars")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Create uploads directory
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# File size limit (10MB in bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Allowed file extensions
ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
ALLOWED_VIDEO_EXTENSIONS = {'.mp4', '.webm', '.ogg', '.mov'}
ALLOWED_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS | ALLOWED_VIDEO_EXTENSIONS

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
templates = Jinja2Templates(directory="templates")

# Add custom filter for JSON parsing in templates
templates.env.filters['from_json'] = lambda x: json.loads(x) if x else []

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

# File handling utility
async def save_upload_file(upload_file: UploadFile, db: Session, post_id: int = None, thread_id: int = None):
    # Check file size
    content = await upload_file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size exceeds 10MB limit")

    # Check file extension
    file_ext = Path(upload_file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type not allowed")

    # Generate unique filename
    unique_filename = f"{int(datetime.utcnow().timestamp())}_{upload_file.filename}"
    file_path = UPLOAD_DIR / unique_filename

    # Save file
    with open(file_path, "wb") as buffer:
        buffer.write(content)

    # Determine file type
    if file_ext in ALLOWED_IMAGE_EXTENSIONS:
        filetype = "image"
    elif file_ext in ALLOWED_VIDEO_EXTENSIONS:
        filetype = "video"
    else:
        filetype = "other"

    # Create attachment record
    attachment = Attachment(
        filename=upload_file.filename,
        filepath=str(file_path),
        filetype=filetype,
        filesize=len(content),
        post_id=post_id,
        thread_id=thread_id
    )
    db.add(attachment)

    return attachment

# Get current user from session
def get_current_user(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

# Check if current user is admin
def get_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

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

    # Check if email exists
    existing_email = db.query(User).filter(User.email == email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")

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
    request.session["is_admin"] = user.is_admin

    print(f"User logged in: {user.username}, ID: {user.id}, Admin: {user.is_admin}")  # DEBUG
    print(f"Session content: {request.session}")  # DEBUG

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
    # Get posts, optionally filtered by tag
    if tag:
        posts = db.query(Post).join(Post.tags).filter(Tag.name == tag).all()
    else:
        posts = db.query(Post).all()

    # Get all unique tags from posts
    all_tags = db.query(Tag).join(Tag.posts).distinct().all()

    return templates.TemplateResponse(
        "main.html",
        {
            "request": request,
            "posts": posts,
            "all_tags": all_tags,
            "selected_tag": tag,
            "username": current_user.username,
            "is_admin": current_user.is_admin
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
    request: Request,
    title: str = Form(...),
    tags: str = Form(default=""),
    content_blocks: str = Form(...),  # JSON string of content blocks
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Sanitization of content and title of the post
    clean_title = sanitize_input(title)

    # Parse content blocks JSON
    try:
        blocks = json.loads(content_blocks)
    except:
        blocks = []

    # Sanitize text blocks
    for block in blocks:
        if block.get('type') == 'text':
            block['content'] = sanitize_input(block['content'])

    # Create new post with author username and timestamp
    new_post = Post(
        title=clean_title,
        content="",  # Legacy field, leave empty for structured posts
        content_blocks=json.dumps(blocks),
        author_username=current_user.username,
        created_at=datetime.utcnow(),
        user_id=current_user.id
    )

    # Process tags
    if tags.strip():
        tag_names = [sanitize_input(tag.strip()) for tag in tags.split(',') if tag.strip()]
        for tag_name in tag_names:
            # Check if tag exists, if not create it
            tag = db.query(Tag).filter(Tag.name == tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.add(tag)
            new_post.tags.append(tag)

    db.add(new_post)
    db.commit()

    return RedirectResponse(url="/main", status_code=303)

# Upload image for post content
@app.post("/upload-image")
async def upload_image(
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        # Check file size
        content = await image.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File size exceeds 10MB limit")

        # Check file extension
        file_ext = Path(image.filename).suffix.lower()
        if file_ext not in ALLOWED_IMAGE_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only image files allowed")

        # Generate unique filename
        unique_filename = f"{int(datetime.utcnow().timestamp())}_{image.filename}"
        file_path = UPLOAD_DIR / unique_filename

        # Save file
        with open(file_path, "wb") as buffer:
            buffer.write(content)

        return {"success": True, "url": f"/uploads/{unique_filename}"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Thread routes
@app.get("/threads", response_class=HTMLResponse)
async def threads_page(
    request: Request,
    tag: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get all threads
    if tag:
        # Filter by tag
        threads = db.query(Thread).join(Thread.tags).filter(Tag.name == tag).all()
    else:
        threads = db.query(Thread).all()

    # Get all unique tags from threads
    all_tags = db.query(Tag).join(Tag.threads).distinct().all()

    return templates.TemplateResponse(
        "threads.html",
        {
            "request": request,
            "threads": threads,
            "all_tags": all_tags,
            "selected_tag": tag,
            "username": current_user.username,
            "is_admin": current_user.is_admin
        }
    )

@app.post("/create-thread")
async def create_thread(
    title: str = Form(...),
    tags: str = Form(default=""),
    attachment: UploadFile = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Sanitization
    clean_title = sanitize_input(title)

    # Create new thread
    new_thread = Thread(
        title=clean_title,
        creator_username=current_user.username,
        created_at=datetime.utcnow(),
        user_id=current_user.id
    )

    # Process tags
    if tags.strip():
        tag_names = [sanitize_input(tag.strip()) for tag in tags.split(',') if tag.strip()]
        for tag_name in tag_names:
            tag = db.query(Tag).filter(Tag.name == tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.add(tag)
            new_thread.tags.append(tag)

    db.add(new_thread)
    db.commit()
    db.refresh(new_thread)

    # Handle file upload
    if attachment and attachment.filename:
        try:
            await save_upload_file(attachment, db, thread_id=new_thread.id)
            db.commit()
        except HTTPException as e:
            db.rollback()
            raise e

    return RedirectResponse(url="/threads", status_code=303)

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

    # Get all messages for this thread, ordered by creation time
    messages = db.query(Message).filter(Message.thread_id == thread_id).order_by(Message.created_at).all()

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
async def send_message(
    thread_id: int,
    content: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check if thread exists
    thread = db.query(Thread).filter(Thread.id == thread_id).first()
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")

    # Sanitize content
    clean_content = sanitize_input(content)

    # Create new message
    new_message = Message(
        content=clean_content,
        author_username=current_user.username,
        created_at=datetime.utcnow(),
        thread_id=thread_id,
        user_id=current_user.id
    )

    db.add(new_message)
    db.commit()

    return RedirectResponse(url=f"/thread/{thread_id}", status_code=303)

# Post Reaction routes
@app.post("/post/{post_id}/react")
async def react_to_post(
    post_id: int,
    reaction_type: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Validate reaction type
    if reaction_type not in ['upvote', 'downvote']:
        raise HTTPException(status_code=400, detail="Invalid reaction type")

    # Check if post exists
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Check if user already reacted
    existing_reaction = db.query(PostReaction).filter(
        PostReaction.post_id == post_id,
        PostReaction.user_id == current_user.id
    ).first()

    if existing_reaction:
        # If same reaction, remove it (toggle)
        if existing_reaction.reaction_type == reaction_type:
            db.delete(existing_reaction)
        else:
            # If different reaction, update it
            existing_reaction.reaction_type = reaction_type
    else:
        # Create new reaction
        new_reaction = PostReaction(
            reaction_type=reaction_type,
            post_id=post_id,
            user_id=current_user.id
        )
        db.add(new_reaction)

    db.commit()
    return RedirectResponse(url="/main", status_code=303)

# Comment routes
@app.post("/post/{post_id}/comment")
async def add_comment(
    post_id: int,
    content: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check if post exists
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Sanitize content
    clean_content = sanitize_input(content)

    # Create new comment
    new_comment = Comment(
        content=clean_content,
        author_username=current_user.username,
        created_at=datetime.utcnow(),
        post_id=post_id,
        user_id=current_user.id
    )

    db.add(new_comment)
    db.commit()

    return RedirectResponse(url="/main", status_code=303)

# Comment Reaction routes
@app.post("/comment/{comment_id}/react")
async def react_to_comment(
    comment_id: int,
    reaction_type: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Validate reaction type
    if reaction_type not in ['upvote', 'downvote']:
        raise HTTPException(status_code=400, detail="Invalid reaction type")

    # Check if comment exists
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Check if user already reacted
    existing_reaction = db.query(CommentReaction).filter(
        CommentReaction.comment_id == comment_id,
        CommentReaction.user_id == current_user.id
    ).first()

    if existing_reaction:
        # If same reaction, remove it (toggle)
        if existing_reaction.reaction_type == reaction_type:
            db.delete(existing_reaction)
        else:
            # If different reaction, update it
            existing_reaction.reaction_type = reaction_type
    else:
        # Create new reaction
        new_reaction = CommentReaction(
            reaction_type=reaction_type,
            comment_id=comment_id,
            user_id=current_user.id
        )
        db.add(new_reaction)

    db.commit()
    return RedirectResponse(url="/main", status_code=303)


# Admin routes
@app.delete("/admin/delete-post/{post_id}")
async def admin_delete_post(
    post_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    # Find the post
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Delete the post (cascade will handle comments, reactions, attachments)
    db.delete(post)
    db.commit()

    return {"success": True}

@app.delete("/admin/delete-comment/{comment_id}")
async def admin_delete_comment(
    comment_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    # Find the comment
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Delete the comment (cascade will handle reactions)
    db.delete(comment)
    db.commit()

    return {"success": True}

@app.delete("/admin/delete-thread/{thread_id}")
async def admin_delete_thread(
    thread_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    # Find the thread
    thread = db.query(Thread).filter(Thread.id == thread_id).first()
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")

    # Delete the thread (cascade will handle messages and attachments)
    db.delete(thread)
    db.commit()

    return {"success": True}
