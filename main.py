from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials,OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
import bcrypt

app = FastAPI()
security = HTTPBasic()

username = "Abel"
password = "A1b2e3"
hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

# FastAPI Basic authentication
@app.get("/basic/login/")
async def get_user(credentials: HTTPBasicCredentials = Depends(security)):

    check_pw = bcrypt.checkpw(credentials.password.encode("utf-8"), hashed_pw)

    if credentials.username == username and check_pw:
        return {"username": credentials.username}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Basic"},
    )

# FastAPI OAuth2

auth_scheme = OAuth2PasswordBearer(tokenUrl="login")
fake_user_db = {
    "Abel":{
        "username":"Abel",
        "password":"1234",
        "token":"abel1234@3"
    }
}
@app.post("/login/")
async def login(form:Annotated[OAuth2PasswordRequestForm,Depends()]):
    username = form.username
    password = form.password
    
    if username not in fake_user_db:
       raise HTTPException(status_code=400,detail="user doesn't exist")
    user = fake_user_db[username]
    
    if user["password"] != password:
        raise HTTPException(status_code=400, detail="Incorrect Password")
    
    return {
        "access_token":user["token"],
        "token_type":"bearer"
    }
    
@app.get("/protected/")
async def protected1(token:str = Depends(auth_scheme)):
    for user in fake_user_db.values():
        if user["token"] == token:
            return {"message": f"Welcome, {user['username']}!"}
    raise HTTPException(status_code=401, detail="Invalid token")
