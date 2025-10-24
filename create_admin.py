"""
Create an admin account
Run this script to create or update an admin user
"""
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/authdb")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_admin():
    db = SessionLocal()

    try:
        # Admin credentials
        admin_username = "admin"
        admin_password = "Admin123!"  # Change this password!
        admin_email = "admin@example.com"

        # Hash password
        hashed_password = pwd_context.hash(admin_password)

        # Check if admin exists
        result = db.execute(
            text("SELECT id FROM users WHERE username = :username"),
            {"username": admin_username}
        ).fetchone()

        if result:
            # Update existing user to admin
            db.execute(
                text("""
                    UPDATE users
                    SET is_admin = 1,
                        hashed_password = :password,
                        email = :email
                    WHERE username = :username
                """),
                {
                    "username": admin_username,
                    "password": hashed_password,
                    "email": admin_email
                }
            )
            print(f"✓ Updated user '{admin_username}' to admin status")
        else:
            # Create new admin user
            db.execute(
                text("""
                    INSERT INTO users (username, hashed_password, email, is_admin, created_at)
                    VALUES (:username, :password, :email, 1, CURRENT_TIMESTAMP)
                """),
                {
                    "username": admin_username,
                    "password": hashed_password,
                    "email": admin_email
                }
            )
            print(f"✓ Created new admin user '{admin_username}'")

        db.commit()

        print("\n" + "="*50)
        print("ADMIN ACCOUNT CREATED/UPDATED")
        print("="*50)
        print(f"Username: {admin_username}")
        print(f"Password: {admin_password}")
        print(f"Email: {admin_email}")
        print("="*50)
        print("\n⚠️  IMPORTANT: Change the password after first login!")

    except Exception as e:
        print(f"✗ Error creating admin: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()
