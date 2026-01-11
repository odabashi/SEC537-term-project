from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_answer: str


class DeviceCheckRequest(BaseModel):
    ip: str


class DiagnosticRequest(BaseModel):
    host: str
