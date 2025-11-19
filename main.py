# from fastapi import FastAPI, Body, File, Form, UploadFile


# app = FastAPI(
#     title="ChimichangApp",
#     description="This is app",
#     summary="Deadpool's favorite app. Nuff said.",
#     version="0.0.1",
#     terms_of_service="http://example.com/terms/",
#     contact={
#         "name": "Deadpoolio the Amazing",
#         "url": "http://x-force.example.com/contact/",
#         "email": "dp@x-force.example.com",
#     },
#     license_info={
#         "name": "Apache 2.0",
#         "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
#     },
# )

# @app.get("/")
# def home():
#     return {"message": "FastAPI is working!"}


# @app.get("/items")
# def get_items() -> dict:
#     return {"items": ["apple", "banana"]}

# @app.post("/items")
# def create_item(item : dict):
#     return {"received_item": item}

# @app.put("/items/{item_id}")
# def update_item(item_id: int, item: dict):
#     return {"id": item_id, "updated_item": item}

# @app.delete("/items/{item_id}")
# def delete_item(item_id: int):
#     return {"deleted": item_id}

# @app.get("/search")
# def search(q: str, limit: int = 10):
#     return {"query": q, "limit": limit}


# from pydantic import BaseModel, Field



# from fastapi import Body

# # What parameters can be passed in Body
# @app.post("/just-string")
# def receive(text: str = Body(None)):
#     return {"text": text}

# # What if i want to specify type in Form
# @app.post("/login")
# def login(username: str = Form(None), password: str = Form(...)):
#     return {"username": username, "password": password}

# @app.post("/upload-file",
#           summary="Upload a JPEG image",
#     description="This endpoint only allows uploading JPEG image files."
# )
# async def upload_file(file: UploadFile = File(..., media_type="image/jpeg")):
#     return {
#         "filename": file.filename,
#         "content_type": file.content_type
#     }

# @app.post("/data", description="Receives a JSON object")
# def receive(data: dict = Body(..., description="Some JSON object")):
#     """Receive a JSON object"""
#     return data



# # ---------------------------
# # REQUEST MODEL
# # ---------------------------
# class User(BaseModel):
#     name: str = Field(..., min_length=3, max_length=20)
#     age: int = Field(..., ge=18, le=60)


# # ---------------------------
# # RESPONSE MODEL
# # ---------------------------
# class UserResponse(BaseModel):
#     id: int = Field(..., example=1)
#     name: str = Field(..., example="John Doe")
#     age: int = Field(..., example=25)


# # ---------------------------
# # ROUTE
# # ---------------------------
# @app.post(
#     "/users",
#     summary="Create a new user",
#     description="This endpoint creates a new user and returns the stored user information.",
#     response_model=UserResponse,
#     tags=["Users"]
# )
# def create_user(user: User):
    
#     # Fake DB save
#     created_user = {
#         "id": 1,
#         "name": user.name,
#         "age": user.age,
#         "additional_info": "This field is not in the response model"
#     }

#     return created_user


# from fastapi import Depends

# def common_logic():
#     return "This runs before the endpoint"

# @app.get("/hello")
# def hello(msg = Depends(common_logic)):
#     return {"message": msg}


from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta, UTC


app = FastAPI()

SECRET_KEY = "secret123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def hash_password(password):
    return pwd_context.hash(password)

# hashPass = hash_password("1234")
# print(verify_password("1234", hashPass))

fake_users_db = {
    "john": {
        "username": "john",
        "full_name": "John Doe",
        "password": hash_password("1234"),
        "role": "user"
    },
    "admin": {
        "username": "admin",
        "full_name": "Admin User",
        "password": hash_password("adminpass"),
        "role": "admin"
    }
}


def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# print(create_token({
#         "sub": "john",
#         "role": "user"
#     }))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
    except JWTError:
        raise HTTPException(401, "Invalid token")

    user = fake_users_db.get(username)
    if not user:
        raise HTTPException(401, "User not found")

    return user


def require_admin(user = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admins only")
    return user


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)

    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(401, "Invalid username or password")

    token = create_token({"sub": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/profile")
def profile(user = Depends(get_current_user)):
    return {"message": "Profile accessed", "user": user}


@app.get("/admin")
def admin_dashboard(admin = Depends(require_admin)):
    return {"message": "Welcome Admin!"}
