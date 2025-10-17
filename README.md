# Registration and Login App

A simple user registration and login application built with FastAPI, PostgreSQL, and Docker.

## Features

- User registration with username and password
- Secure password hashing using bcrypt
- User login with credential verification
- PostgreSQL database for data persistence
- Docker containerization for easy deployment

## Project Structure

```
.
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── main.py
├── templates/
│   ├── register.html
│   ├── login.html
│   └── main.html
└── static/
    └── css/
        ├── register.css
        ├── login.css
        └── main.css
```

## Prerequisites

- Docker
- Docker Compose

## Installation and Setup

1. Clone or download this project

2. Build and start the containers:
   ```bash
   docker-compose up --build -d
   ```

3. The application will be available at `http://localhost:8000`

## Usage

1. Open `http://localhost:8000` in your browser
2. Register a new account with a username and password
3. After registration, you'll be redirected to the login page
4. Login with your credentials
5. Upon successful login, you'll see the main welcome page

## Stopping the Application

```bash
docker-compose down
```

To also remove the database volume:
```bash
docker-compose down -v
```

## Ports

- Web application: `8000`
- PostgreSQL database: `5433` (internal: `5432`)

