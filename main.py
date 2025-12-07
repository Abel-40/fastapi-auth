from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials,OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from pydantic import BaseModel,EmailStr
import bcrypt

app = FastAPI()
auth_scheme = OAuth2PasswordBearer(tokenUrl = "login")
plain_password1 = "1234"
plain_password2 = "12345"
fake_db = {
    "Abel":{
        "username":"Abel",
        "full_name":"Abel Addis",
        "email":"abel@gmail.com",
        "hashed_password":bcrypt.hashpw(plain_password1.encode("utf-8"), bcrypt.gensalt()),
        "disabled":False
    },
    "Abrish":{
        "username":"Abrish",
        "full_name":"Aberham Aserat",
        "email":"Aberham@gmail.com",
        "hashed_password":bcrypt.hashpw(plain_password2.encode("utf-8"), bcrypt.gensalt()),
        "disabled":True
    }
}

class User(BaseModel):
    username:str
    full_name:str | None
    email:EmailStr
    disabled:bool

class UserDbIn(User):
    hashed_password: str

def get_user(db,username:str):
    if username in db:
        user = db[username]
        return UserDbIn(**user)
def fake_decode_token(token:str):
    user = get_user(fake_db,token)
    return user

async def get_current_user(token:str = Depends(auth_scheme)):
    user = fake_decode_token(token)
    return user
async def get_current_active_user(user:Annotated[UserDbIn,Depends(get_current_user)]):
    if user.disabled == True:
        raise HTTPException(status_code=401,detail="Inactive User")
    return user

@app.post("/login/")
async def login(form_data:Annotated[OAuth2PasswordRequestForm,Depends()]):
    username = form_data.username
    password = form_data.password
    
    if  fake_db.get(username) == None:
        raise HTTPException(status_code = 400, detail = "Incorrect password or username.")
    user = UserDbIn(**fake_db.get(username))
    if not bcrypt.checkpw(password.encode("utf-8"),user.hashed_password.encode("utf-8")):
        raise HTTPException(status_code=400,detail = "Incorrect password or username.")
    
    return {
        "access_token":user.username,
        "token_type":"bearer"
    }
@app.get("/users/me")
async def me(current_user:Annotated[UserDbIn,Depends(get_current_active_user)]):
    return current_user
    