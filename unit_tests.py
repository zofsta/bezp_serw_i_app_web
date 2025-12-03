"""
Testy jednostkowe dla aplikacji FastAPI
Testowane komponenty:
1. Modele walidacyjne Pydantic (RegisterRequest, LoginRequest, PostRequest)
2. Modele bazy danych (properties: author_username, creator_username)
"""

import os
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# WAŻNE: Ustawić DATABASE_URL PRZED importem main.py
# Inaczej main.py wywoła sys.exit(1) i zabija testy
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from main import (
    RegisterRequest, 
    LoginRequest, 
    PostRequest,
    User,
    Post,
    Comment,
    Thread,
    ThreadMessage,
    Base
)


# testy - konfiguracja testowej bazy danych

@pytest.fixture(scope="function")
def test_db():
    """Tworzy tymczasową bazę danych SQLite w pamięci dla testów"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()


@pytest.fixture
def sample_user(test_db):
    """Tworzy przykładowego użytkownika do testów"""
    user = User(
        username="testuser",
        hashed_password="hashed_password_123",
        email="test@example.com",
        is_admin=0
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def sample_post(test_db, sample_user):
    """Tworzy przykładowy post do testów"""
    post = Post(
        title="Test Post",
        content="Test content",
        user_id=sample_user.id
    )
    test_db.add(post)
    test_db.commit()
    test_db.refresh(post)
    return post


# testy modelu RegisterRequest - rejestracja

class TestRegisterRequest:
    """Testy walidacji dla modelu RegisterRequest"""

    # testy pozytywne

    def test_valid_registration(self):
        """Test poprawnej rejestracji ze wszystkimi wymaganiami"""
        data = RegisterRequest(
            username="validuser",
            password="SecurePass123!",
            email="user@example.com"
        )
        assert data.username == "validuser"
        assert data.email == "user@example.com"

    def test_username_with_underscores(self):
        """Test username z underscorami"""
        data = RegisterRequest(
            username="valid_user_123",
            password="SecurePass123!",
            email="user@example.com"
        )
        assert data.username == "valid_user_123"

    def test_username_normalization_to_lowercase(self):
        """Test normalizacji username do małych liter"""
        data = RegisterRequest(
            username="ValidUser",
            password="SecurePass123!",
            email="user@example.com"
        )
        assert data.username == "validuser"

    def test_email_normalization_to_lowercase(self):
        """Test normalizacji email do małych liter"""
        data = RegisterRequest(
            username="validuser",
            password="SecurePass123!",
            email="User@EXAMPLE.COM"
        )
        assert data.email == "user@example.com"

    def test_password_with_various_special_characters(self):
        """Test hasła z różnymi znakami specjalnymi"""
        special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '.', '?', ':', '{', '}', '|', '<', '>']
        for char in special_chars:
            data = RegisterRequest(
                username="validuser",
                password=f"SecurePass123{char}",
                email="user@example.com"
            )
            assert data.password == f"SecurePass123{char}"

    def test_minimum_valid_username_length(self):
        """Test minimalnej długości username (3 znaki)"""
        data = RegisterRequest(
            username="abc",
            password="SecurePass123!",
            email="user@example.com"
        )
        assert data.username == "abc"

    def test_maximum_valid_username_length(self):
        """Test maksymalnej długości username (20 znaków)"""
        data = RegisterRequest(
            username="a" * 20,
            password="SecurePass123!",
            email="user@example.com"
        )
        assert len(data.username) == 20

    def test_minimum_valid_password_length(self):
        """Test minimalnej długości hasła (8 znaków)"""
        data = RegisterRequest(
            username="validuser",
            password="Secure1!",
            email="user@example.com"
        )
        assert len(data.password) == 8

    # testy negatywne - username

    def test_username_too_short(self):
        """Test username za krótkiego (<3 znaki)"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="ab",
                password="SecurePass123!",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("min_length" in str(error) for error in errors)

    def test_username_too_long(self):
        """Test username za długiego (>20 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="a" * 21,
                password="SecurePass123!",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("max_length" in str(error) for error in errors)

    def test_username_with_spaces(self):
        """Test username ze spacjami"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="user name",
                password="SecurePass123!",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("Username może zawierać tylko litery, cyfry i podkreślenia" in str(error) for error in errors)

    def test_username_with_special_characters(self):
        """Test username ze znakami specjalnymi"""
        invalid_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '=']
        for char in invalid_chars:
            with pytest.raises(ValidationError):
                RegisterRequest(
                    username=f"user{char}name",
                    password="SecurePass123!",
                    email="user@example.com"
                )

    def test_username_starting_with_number(self):
        """Test username zaczynającego się od cyfry"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="123user",
                password="SecurePass123!",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("Username nie może zaczynać się od cyfry" in str(error) for error in errors)

    # testy negatywne - hasło

    def test_password_too_short(self):
        """Test hasła za krótkiego (<8 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="Short1!",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("min_length" in str(error) for error in errors)

    def test_password_without_uppercase(self):
        """Test hasła bez wielkiej litery"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="securepass123!",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("Hasło musi zawierać przynajmniej jedną wielką literę" in str(error) for error in errors)

    def test_password_without_lowercase(self):
        """Test hasła bez małej litery"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="SECUREPASS123!",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("Hasło musi zawierać przynajmniej jedną małą literę" in str(error) for error in errors)

    def test_password_without_digit(self):
        """Test hasła bez cyfry"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="SecurePass!",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("Hasło musi zawierać przynajmniej jedną cyfrę" in str(error) for error in errors)

    def test_password_without_special_character(self):
        """Test hasła bez znaku specjalnego"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="SecurePass123",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("Hasło musi zawierać przynajmniej jeden znak specjalny" in str(error) for error in errors)

    def test_password_too_long(self):
        """Test hasła za długiego (>100 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="A" * 101 + "a1!",
                email="user@example.com"
            )
        errors = exc_info.value.errors()
        assert any("max_length" in str(error) for error in errors)

# testy negatywne - email

    def test_email_without_at_symbol(self):
        """Test email bez znaku @"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="SecurePass123!",
                email="userexample.com"
            )
        errors = exc_info.value.errors()
        assert any("Nieprawidłowy format adresu email" in str(error) for error in errors)

    def test_email_without_domain(self):
        """Test email bez domeny"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="SecurePass123!",
                email="user@"
            )
        errors = exc_info.value.errors()
        assert any("Nieprawidłowy format adresu email" in str(error) for error in errors)

    def test_email_without_tld(self):
        """Test email bez TLD (top-level domain)"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="SecurePass123!",
                email="user@example"
            )
        errors = exc_info.value.errors()
        assert any("Nieprawidłowy format adresu email" in str(error) for error in errors)

    def test_email_with_spaces(self):
        """Test email ze spacjami"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="SecurePass123!",
                email="user name@example.com"
            )
        errors = exc_info.value.errors()
        assert any("Nieprawidłowy format adresu email" in str(error) for error in errors)

    def test_email_too_short(self):
        """Test email za krótkiego (<5 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="SecurePass123!",
                email="a@b"
            )
        errors = exc_info.value.errors()
        assert any("min_length" in str(error) for error in errors)

    def test_email_too_long(self):
        """Test email za długiego (>100 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                username="validuser",
                password="SecurePass123!",
                email="a" * 95 + "@example.com"
            )
        errors = exc_info.value.errors()
        assert any("max_length" in str(error) for error in errors)


# testy logowania

class TestLoginRequest:
    """Testy walidacji dla modelu LoginRequest"""

    def test_valid_login(self):
        """Test poprawnego logowania"""
        data = LoginRequest(
            username="validuser",
            password="anypassword"
        )
        assert data.username == "validuser"
        assert data.password == "anypassword"

    def test_username_too_short(self):
        """Test username za krótkiego (<3 znaki)"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                username="ab",
                password="password"
            )
        errors = exc_info.value.errors()
        assert any("min_length" in str(error) for error in errors)

    def test_username_too_long(self):
        """Test username za długiego (>20 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                username="a" * 21,
                password="password"
            )
        errors = exc_info.value.errors()
        assert any("max_length" in str(error) for error in errors)

    def test_empty_password(self):
        """Test pustego hasła"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                username="validuser",
                password=""
            )
        errors = exc_info.value.errors()
        assert any("min_length" in str(error) for error in errors)

    def test_password_too_long(self):
        """Test hasła za długiego (>100 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                username="validuser",
                password="a" * 101
            )
        errors = exc_info.value.errors()
        assert any("max_length" in str(error) for error in errors)

# testy tworzenia postow

class TestPostRequest:
    """Testy walidacji dla modelu PostRequest"""

# testy pozytywne

    def test_valid_post(self):
        """Test poprawnego posta"""
        data = PostRequest(
            title="Valid Post Title",
            content="This is valid content with more than 10 characters"
        )
        assert data.title == "Valid Post Title"
        assert data.content == "This is valid content with more than 10 characters"

    def test_title_minimum_length(self):
        """Test minimalnej długości tytułu (5 znaków)"""
        data = PostRequest(
            title="Title",
            content="Valid content here"
        )
        assert len(data.title) == 5

    def test_title_maximum_length(self):
        """Test maksymalnej długości tytułu (100 znaków)"""
        data = PostRequest(
            title="a" * 100,
            content="Valid content here"
        )
        assert len(data.title) == 100

    def test_content_minimum_length(self):
        """Test minimalnej długości treści (10 znaków)"""
        data = PostRequest(
            title="Valid Title",
            content="1234567890"
        )
        assert len(data.content) == 10

    def test_content_maximum_length(self):
        """Test maksymalnej długości treści (5000 znaków)"""
        data = PostRequest(
            title="Valid Title",
            content="a" * 5000
        )
        assert len(data.content) == 5000

    def test_title_strips_whitespace(self):
        """Test usuwania białych znaków z tytułu"""
        data = PostRequest(
            title="  Valid Title  ",
            content="Valid content here"
        )
        assert data.title == "Valid Title"

    def test_content_strips_whitespace(self):
        """Test usuwania białych znaków z treści"""
        data = PostRequest(
            title="Valid Title",
            content="  Valid content here  "
        )
        assert data.content == "Valid content here"

# testy negatywne - tytuł

    def test_title_too_short(self):
        """Test tytułu za krótkiego (<5 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            PostRequest(
                title="Abcd",
                content="Valid content here"
            )
        errors = exc_info.value.errors()
        assert any("min_length" in str(error) for error in errors)

    def test_title_too_long(self):
        """Test tytułu za długiego (>100 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            PostRequest(
                title="a" * 101,
                content="Valid content here"
            )
        errors = exc_info.value.errors()
        assert any("max_length" in str(error) for error in errors)

    def test_title_only_whitespace(self):
        """Test tytułu zawierającego tylko spacje"""
        with pytest.raises(ValidationError) as exc_info:
            PostRequest(
                title="     ",
                content="Valid content here"
            )
        errors = exc_info.value.errors()
        assert any("Tytuł nie może być pusty" in str(error) for error in errors)

    def test_title_only_tabs(self):
        """Test tytułu zawierającego tylko tabulatory"""
        with pytest.raises(ValidationError) as exc_info:
            PostRequest(
                title="\t\t\t\t\t",
                content="Valid content here"
            )
        errors = exc_info.value.errors()
        assert any("Tytuł nie może być pusty" in str(error) for error in errors)

# testy negatywne - treść

    def test_content_too_short(self):
        """Test treści za krótkiej (<10 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            PostRequest(
                title="Valid Title",
                content="Short"
            )
        errors = exc_info.value.errors()
        assert any("min_length" in str(error) for error in errors)

    def test_content_too_long(self):
        """Test treści za długiej (>5000 znaków)"""
        with pytest.raises(ValidationError) as exc_info:
            PostRequest(
                title="Valid Title",
                content="a" * 5001
            )
        errors = exc_info.value.errors()
        assert any("max_length" in str(error) for error in errors)

    def test_content_only_whitespace(self):
        """Test treści zawierającej tylko spacje"""
        with pytest.raises(ValidationError) as exc_info:
            PostRequest(
                title="Valid Title",
                content="          "
            )
        errors = exc_info.value.errors()
        assert any("Treść nie może być pusta" in str(error) for error in errors)

    def test_content_only_newlines(self):
        """Test treści zawierającej tylko znaki nowej linii"""
        with pytest.raises(ValidationError) as exc_info:
            PostRequest(
                title="Valid Title",
                content="\n\n\n\n\n\n\n\n\n\n"
            )
        errors = exc_info.value.errors()
        assert any("Treść nie może być pusta" in str(error) for error in errors)

class TestDatabaseModelProperties:
    """Testy właściwości (properties) modeli bazy danych"""

    def test_post_author_username(self, test_db, sample_user, sample_post):
        """Test property Post.author_username"""
        assert sample_post.author_username == "testuser"

    def test_post_author_username_when_author_is_none(self, test_db):
        """Test Post.author_username gdy autor nie istnieje"""
        post = Post(
            title="Test Post",
            content="Test content",
            user_id=None
        )
        test_db.add(post)
        test_db.commit()
        assert post.author_username == "Unknown"

    def test_comment_author_username(self, test_db, sample_user, sample_post):
        """Test property Comment.author_username"""
        comment = Comment(
            content="Test comment",
            post_id=sample_post.id,
            user_id=sample_user.id
        )
        test_db.add(comment)
        test_db.commit()
        test_db.refresh(comment)
        assert comment.author_username == "testuser"

    def test_comment_author_username_when_author_is_none(self, test_db, sample_post):
        """Test Comment.author_username gdy autor nie istnieje"""
        comment = Comment(
            content="Test comment",
            post_id=sample_post.id,
            user_id=None
        )
        test_db.add(comment)
        test_db.commit()
        assert comment.author_username == "Unknown"

    def test_thread_creator_username(self, test_db, sample_user):
        """Test property Thread.creator_username"""
        thread = Thread(
            title="Test Thread",
            user_id=sample_user.id
        )
        test_db.add(thread)
        test_db.commit()
        test_db.refresh(thread)
        assert thread.creator_username == "testuser"

    def test_thread_creator_username_when_creator_is_none(self, test_db):
        """Test Thread.creator_username gdy twórca nie istnieje"""
        thread = Thread(
            title="Test Thread",
            user_id=None
        )
        test_db.add(thread)
        test_db.commit()
        assert thread.creator_username == "Unknown"

    def test_thread_message_author_username(self, test_db, sample_user):
        """Test property ThreadMessage.author_username"""
        thread = Thread(
            title="Test Thread",
            user_id=sample_user.id
        )
        test_db.add(thread)
        test_db.commit()
        test_db.refresh(thread)

        message = ThreadMessage(
            content="Test message",
            thread_id=thread.id,
            user_id=sample_user.id
        )
        test_db.add(message)
        test_db.commit()
        test_db.refresh(message)
        assert message.author_username == "testuser"

    def test_thread_message_author_username_when_author_is_none(self, test_db, sample_user):
        """Test ThreadMessage.author_username gdy autor nie istnieje"""
        thread = Thread(
            title="Test Thread",
            user_id=sample_user.id
        )
        test_db.add(thread)
        test_db.commit()
        test_db.refresh(thread)

        message = ThreadMessage(
            content="Test message",
            thread_id=thread.id,
            user_id=None
        )
        test_db.add(message)
        test_db.commit()
        assert message.author_username == "Unknown"


class TestDatabaseModelRelationships:
    """Testy relacji między modelami bazy danych"""

    def test_post_has_author_relationship(self, test_db, sample_user, sample_post):
        """Test relacji Post -> User (author)"""
        assert sample_post.author is not None
        assert sample_post.author.id == sample_user.id
        assert sample_post.author.username == "testuser"

    def test_post_has_comments_relationship(self, test_db, sample_user, sample_post):
        """Test relacji Post -> Comments"""
        comment1 = Comment(content="Comment 1", post_id=sample_post.id, user_id=sample_user.id)
        comment2 = Comment(content="Comment 2", post_id=sample_post.id, user_id=sample_user.id)
        test_db.add_all([comment1, comment2])
        test_db.commit()
        test_db.refresh(sample_post)
        assert len(sample_post.comments) == 2

    def test_comment_has_post_relationship(self, test_db, sample_user, sample_post):
        """Test relacji Comment -> Post"""
        comment = Comment(content="Test comment", post_id=sample_post.id, user_id=sample_user.id)
        test_db.add(comment)
        test_db.commit()
        test_db.refresh(comment)
        assert comment.post is not None
        assert comment.post.id == sample_post.id

    def test_thread_has_messages_relationship(self, test_db, sample_user):
        """Test relacji Thread -> Messages"""
        thread = Thread(title="Test Thread", user_id=sample_user.id)
        test_db.add(thread)
        test_db.commit()
        test_db.refresh(thread)

        msg1 = ThreadMessage(content="Message 1", thread_id=thread.id, user_id=sample_user.id)
        msg2 = ThreadMessage(content="Message 2", thread_id=thread.id, user_id=sample_user.id)
        test_db.add_all([msg1, msg2])
        test_db.commit()
        test_db.refresh(thread)
        assert len(thread.messages) == 2

if __name__ == "__main__":

    pytest.main([__file__, "-v", "--tb=short"])
