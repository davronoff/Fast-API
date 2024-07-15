import sys

from starlette.responses import RedirectResponse

sys.path.append("..")

from fastapi import Depends, HTTPException, status, APIRouter, Request, Response, Form
from pydantic import BaseModel
import models as models
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from fastapi.responses import HTMLResponse
from routers.auth import get_current_user, get_password_hash, verify_password
import os
from fastapi.templating import Jinja2Templates


SECRET_KEY = "KlgH6AzYDeZeGwD288to79I3vTHT8wp7"
ALGORITHM = "HS256"

models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory=os.path.abspath("templates"))


router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={401: {"user": "Not authorized"}}
)


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


class UserVerification(BaseModel):
    username: str
    password: str
    new_password: str


@router.get("/edit-password", response_class=HTMLResponse)
async def password(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("edit-user-password.html", {"request": request, "user": user})


@router.post("/edit-password", response_class=HTMLResponse)
async def change_password(request: Request, username: str = Form(...),
                          password: str = Form(...), password2: str = Form(...),
                          db: Session = Depends(get_db)):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    validation = db.query(models.Users).filter(models.Users.id == user.get("id")).first()

    msg = "Invalid Password or Username"
    if validation.username != username:
        msg = "Wrong Account"

    user_data = db.query(models.Users).filter(models.Users.username == username).first()

    if user_data is not None:
        if username == user_data.username and verify_password(password, user_data.hashed_password):
            user_data.hashed_password = get_password_hash(password2)
            db.add(user_data)
            db.commit()
            msg = "Password Updated"

    return templates.TemplateResponse("edit-user-password.html", {"request": request, "msg": msg, "user": user})

