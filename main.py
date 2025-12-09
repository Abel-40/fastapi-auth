from fastapi import FastAPI, Depends, HTTPException, status,Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials,OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from fastapi.responses import JSONResponse
from datetime import timedelta,datetime,timezone
from pydantic import EmailStr,BaseModel
import jwt
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from config import settings
app = FastAPI()
SECRET_KEY=settings.SECRET_KEY
ALGORITHM=settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES=settings.ACCESS_TOKEN_EXPIRE_MINUTES
password_lib = PasswordHash.recommended()

auth_secheme = OAuth2PasswordBearer(tokenUrl="login")


def password_hasher(password):
    return password_lib.hash(password)
def password_verifier(plain_password,hashed_password):
    return password_lib.verify(plain_password,hashed_password)

class User(BaseModel):
    username:str
    full_name:str | None
    email:EmailStr
    disabled:bool

class UserDbIn(User):
    hashed_password: str

class Token(BaseModel):
    access_token:str
    token_type:str
    
class TokenData(BaseModel):
    username:str
    
fake_users_db = {
    "abel": {
        "username": "abel",
        "full_name": "Abel Addis",
        "email": "abel@example.com",
        "hashed_password": password_hasher("1234"),
        "disabled": False,
    },
    "janedoe": {
        "username": "janedoe",
        "full_name": "Jane Doe",
        "email": "janedoe@example.com",
        "hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$g2NMBhMfk1ZrZvM9uCnTrw$sWWGv3xyobY/uEyOYqbtF9su2eCjbmu3MZwXpmh2m1w",
        "disabled": False,
    },
    "michael": {
        "username": "michael",
        "full_name": "Michael Smith",
        "email": "michael@example.com",
        "hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$h9Jv9H9fIL45d5aEkvUEPg$7S4IIEOVtsEFr7DFuiKSa23IRmODWUYGLCjk1O4X6mE",
        "disabled": True,
    },
    "sarah": {
        "username": "sarah",
        "full_name": "Sarah Johnson",
        "email": "sarah@example.com",
        "hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$Sy0PxRKvZPjiG7n0D2mxTQ$1GnDVWYta9UzZxUTQNlAXuxbHoU79rsPGq47B9jyTgI",
        "disabled": False,
    },
}


def get_user(db, username):
    if username in db:
        user = db[username]
        return UserDbIn(**user)
def authenticate_user(db,username,password):
    user = get_user(db,username)
    if not user:
        return False
    if not password_verifier(password,user.hashed_password):
        return False
    return user

def create_acces_token(data:dict,expire_delta:timedelta | None = None):
    to_encode = data.copy()
    if expire_delta:
        expire = datetime.now(timezone.utc) + expire_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days = 15)
    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY,ALGORITHM)
    
    return encoded_jwt

async def get_current_user(token:Annotated[str,Depends(auth_secheme)]):
    credentials_Exception = HTTPException(
        status_code = 401,
        detail = "Invalid Credentials",
        headers = {"WWW-Authenticate":"Bearer"}
    )
    
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username == None:
            raise credentials_Exception
        token_data = TokenData(username = username)
        user = get_user(fake_users_db,token_data.username)
        if user == None:
            raise credentials_Exception
        return user
    except InvalidTokenError:
         raise credentials_Exception
        
async def get_current_active_user(current_user:Annotated[get_current_user,Depends()]):
    credentials_Exception = HTTPException(
        status_code = 401,
        detail = "Inactive User",
        headers = {"WWW-Authenticate":"Bearer"}
    )
    if current_user.disabled:
        raise credentials_Exception
    return current_user

@app.post("/login/")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    username = form_data.username
    password = form_data.password

    user = authenticate_user(fake_users_db, username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Create tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=7)

    access_token = create_acces_token(
        data={"sub": user.username},
        expire_delta=access_token_expires
    )
    refresh_token = create_acces_token(
        data={"sub": user.username},
        expire_delta=refresh_token_expires
    )

    # Prepare response
    response = JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "bearer"
        }
    )

    # Set HTTP-only refresh cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # True if using HTTPS
        samesite="lax",
        max_age=7 * 24 * 60 * 60,
    )

    return response


@app.post("/refresh/")
async def refresh_token(request: Request):
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Create new access token
    new_access_token = create_acces_token(
        data={"sub": username},
        expire_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {"access_token": new_access_token, "token_type": "bearer"}

    
    
@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]