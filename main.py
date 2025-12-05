from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import bcrypt

app = FastAPI()
security = HTTPBasic()

username = "Abel"
password = "A1b2e3"
hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

@app.get("/")
async def get_user(credentials: HTTPBasicCredentials = Depends(security)):

    check_pw = bcrypt.checkpw(credentials.password.encode("utf-8"), hashed_pw)

    if credentials.username == username and check_pw:
        return {"username": credentials.username}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Basic"},
    )
