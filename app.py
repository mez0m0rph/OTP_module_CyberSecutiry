from fastapi import FastAPI
from pydantic import BaseModel

from auth import register_user, login_user
from entropy import get_entropy, has_enough_entropy


app = FastAPI(
    title="OTP Module CyberSecurity",
    description="Authorization service with password hash and TOTP",
    version="1.0.0"
)


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str


@app.get("/")
def root():
    return {
        "message": "OTP Module CyberSecurity is running"
    }


@app.get("/entropy")
def entropy_status():
    return {
        "entropy": get_entropy(),
        "has_enough_entropy": has_enough_entropy()
    }


@app.post("/register")
def register(request: RegisterRequest):
    return register_user(request.username, request.password)


@app.post("/login")
def login(request: LoginRequest):
    return login_user(
        request.username,
        request.password,
        request.totp_code
    )
