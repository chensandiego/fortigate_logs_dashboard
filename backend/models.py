from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str

class LogSearchRequest(BaseModel):
    query: str = "*"
    days: int = 3
    limit: int = 1000
