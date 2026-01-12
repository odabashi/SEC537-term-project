from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_answer: str


class DeviceCheckRequest(BaseModel):
    ip: str


class DeviceAddRequest(BaseModel):
    name: str
    ip: str
    type: str


class DiagnosticRequest(BaseModel):
    host: str
