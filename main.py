import datetime
from datetime import timedelta
from fastapi import FastAPI, Path, HTTPException, Depends,status
from pydantic import BaseModel, Field
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from jose import jwt,JWTError


books_database = []
USERS = {}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 30




class Book(BaseModel):
    name: str = Field(...,description="enter name of the book.", examples=["learn c++"])
    author: str = Field(..., description="enter author name of the book.", examples=["jhon wick"])
    category_of_book: str = Field(..., description="enter category of book.", examples=["comedy", "learning"])
    price: int = Field(..., description="enter price of the book.", examples=[100], gt=0)
    quantity: int = Field(..., description="enter quantity of the book.", examples=[5], gt=0)

class User(BaseModel):
    username:str = Field(..., description="enter username of the user.", examples=["admin"])
    password:str = Field(..., description="enter password of the user.", examples=["password123"])

class Token(BaseModel):
    access_token:str
    token_type:str


def create_token(data:dict,expires_time:timedelta):
    to_encode = data.copy()
    if expires_time:
        expire = datetime.datetime.utcnow() + expires_time
    else:
        expire = datetime.datetime.utcnow() + timedelta(minutes=15)
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token:str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "token"}
            )
        return username
    except JWTError:
        raise HTTPException(401,"Could not validate credentials")


@app.get("/",tags=["Health Check."])
def welcome():
    return {"message": "Welcome To The Books Catelog"}


@app.post("/register",tags=["Register."])
def add_user(form_data:OAuth2PasswordRequestForm = Depends()):
    USERS.update({form_data.username:{form_data.username:form_data.password}})
    return {f"You Have Successfully Registered : {form_data.username}"}



@app.get("/all_Books",tags=["Book Catelog."])
def get_all_books(scheme = Depends(oauth2_scheme)):
    if books_database == []:
        return HTTPException(status_code=404, detail="No Books Found")
    return books_database

@app.post("/Add_A_Book",tags=["Book Catelog."])
async def add_a_book(book:Book,scheme = Depends(oauth2_scheme)):
    global books_database
    name = book.name
    for index in range(len(books_database)):
        if name in books_database[index]["name"]:
            return HTTPException(status_code=400, detail="Book already exists")

    books_database.append(
        {"name": book.name, "author": book.author, "category": book.category_of_book, "price": book.price,
         "quantity": book.quantity})
    return {"message": "Book Added Successfully"}


@app.put("/edit_book",tags=["Book Catelog."])
def edit_book(book:Book, scheme = Depends(oauth2_scheme), name: str = None):
    for index in range(len(books_database)):
        if books_database[index]["name"] == name:
            books_database[index] = {"name": book.name, "author": book.author, "category": book.category_of_book,
                                     "price": book.new_price, "quantity": book.quantity}
            return {"message": "Book Edited Successfully"}
    return HTTPException(status_code=404, detail="Book not found")

@app.patch("/Book",tags=["Book Catelog."])
async def get_book(book:Book, scheme = Depends(oauth2_scheme), name: str | None = None):
    for index in range(len(books_database)):
        if books_database[index]["name"] == name:
            return books_database[index]
        else:
            pass
    return HTTPException(status_code=404, detail="Book not found")


@app.delete("/delete_book",tags=["Book Catelog."])
def delete_book(book:Book, scheme = Depends(oauth2_scheme), name: str = None):
    for index in range(len(books_database)):
        if books_database[index]["name"] == name:
            books_database.remove(books_database[index])
            return {"message": "Book Deleted Successfully"}
    return HTTPException(status_code=404, detail="Book Not Found")



@app.post("/token",tags=["User and Token."])
def login(form_data:OAuth2PasswordRequestForm = Depends()):
    username = USERS.get(form_data.username)

    if not USERS.get(form_data.username) and USERS["password"] != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "token"}
        )
    access_token_expired = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    access_token = create_token(data={"sub":form_data.username},expires_time=access_token_expired)
    return {"access_token":access_token, "token_type":"bearer"}


@app.get("/user",tags=["User and Token."])
def get_user(username:str = Depends(verify_token)):
    return {f"welcome {username}! You are logged in as {username}"}


