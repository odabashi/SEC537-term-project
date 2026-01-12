from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_answer: str


class DeviceCheckRequest(BaseModel):
    ip: str
    port: int = 502


class DeviceAddRequest(BaseModel):
    name: str
    ip: str
    type: str
    port: int = 502


class DiagnosticRequest(BaseModel):
    host: str
