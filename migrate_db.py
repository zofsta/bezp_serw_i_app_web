"""
Database migration script to add new columns and tables
Run this once to update your existing database schema
"""
import os
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/authdb")
engine = create_engine(DATABASE_URL)

def run_migration():
    with engine.connect() as conn:
        print("Starting database migration...")

        # Add new columns to users table
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin INTEGER DEFAULT 0"))
            print("✓ Added is_admin column to users")
        except Exception as e:
            print(f"  is_admin column: {e}")

        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
            print("✓ Added created_at column to users")
        except Exception as e:
            print(f"  created_at column: {e}")

        # Add new columns to posts table
        try:
            conn.execute(text("ALTER TABLE posts ADD COLUMN IF NOT EXISTS content_blocks TEXT"))
            print("✓ Added content_blocks column to posts")
        except Exception as e:
            print(f"  content_blocks column: {e}")

        try:
            conn.execute(text("ALTER TABLE posts ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
            print("✓ Added created_at column to posts")
        except Exception as e:
            print(f"  created_at column: {e}")

        try:
            conn.execute(text("ALTER TABLE posts ALTER COLUMN title TYPE VARCHAR(200)"))
            print("✓ Updated title column length in posts")
        except Exception as e:
            print(f"  title column update: {e}")

        try:
            conn.execute(text("ALTER TABLE posts ALTER COLUMN content TYPE TEXT"))
            print("✓ Updated content column type in posts")
        except Exception as e:
            print(f"  content column update: {e}")

        try:
            conn.execute(text("ALTER TABLE posts ALTER COLUMN user_id SET NOT NULL"))
            conn.execute(text("ALTER TABLE posts ADD CONSTRAINT fk_posts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"))
            print("✓ Updated posts foreign key constraint")
        except Exception as e:
            print(f"  posts foreign key: {e}")

        # Create tags table
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS tags (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR UNIQUE NOT NULL
                )
            """))
            print("✓ Created tags table")
        except Exception as e:
            print(f"  tags table: {e}")

        # Create post_tags table
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS post_tags (
                    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
                    tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE,
                    PRIMARY KEY (post_id, tag_id)
                )
            """))
            print("✓ Created post_tags table")
        except Exception as e:
            print(f"  post_tags table: {e}")

        # Create comments table
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS comments (
                    id SERIAL PRIMARY KEY,
                    content TEXT NOT NULL,
                    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            print("✓ Created comments table")
        except Exception as e:
            print(f"  comments table: {e}")

        # Create post_reactions table
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS post_reactions (
                    id SERIAL PRIMARY KEY,
                    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    reaction_type VARCHAR(20) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(post_id, user_id)
                )
            """))
            print("✓ Created post_reactions table")
        except Exception as e:
            print(f"  post_reactions table: {e}")

        # Create comment_reactions table
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS comment_reactions (
                    id SERIAL PRIMARY KEY,
                    comment_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    reaction_type VARCHAR(20) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(comment_id, user_id)
                )
            """))
            print("✓ Created comment_reactions table")
        except Exception as e:
            print(f"  comment_reactions table: {e}")

        # Create indexes
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC)"))
            print("✓ Created index on posts.created_at")
        except Exception as e:
            print(f"  posts index: {e}")

        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)"))
            print("✓ Created index on comments.post_id")
        except Exception as e:
            print(f"  comments index: {e}")

        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name)"))
            print("✓ Created index on tags.name")
        except Exception as e:
            print(f"  tags index: {e}")

        conn.commit()
        print("\n✓ Migration completed successfully!")

if __name__ == "__main__":
    run_migration()
