from fastapi import APIRouter, HTTPException, Depends, status, Path, Query, Security
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.db import get_db
from src.repository import users as rep_users
from src.schemas.user import UserSchema, TokenSchema, UserResponseSchema
from src.services.auth import auth_service


router = APIRouter(prefix='/auth', tags=['auth'])
""" Клас [HTTPBearer] (функтор!) може створювати таку ж саму функцію [get_current_user] яку написано з нуля у класі [Auth]
    файл services/auth.py. [HTTPBearer] дiстає Bearer-token з прийшедшого HTTP-запиту по строго встановленiй схемi:
        - якщо помилка - повертаться 403.FORBIDDEN;
        - якщо refresh-token спивпадає з записом у БД, вiн повертає класс [HTTPAuthorizationCredentials] у якого в кортежi
    параметри <scheme> та <credentials>.
    У цiй реалiзації <scheme>="Bearer", <credentials>="строкове представлення refresh-token".
    Функтор [get_refresh_token] додається в параметри функції refresh_token:
        <credentials: HTTPAuthorizationCredentials = Security(get_refresh_token)>, але, як з'ясувалося, замiсть [Security()]
        може бути й [Depends()]... """
get_refresh_token = HTTPBearer()


@router.post("/signup", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
async def signup(body: UserSchema, db: AsyncSession = Depends(get_db)):
    exist_user = await rep_users.get_user_by_email(body.email, db)
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    body.password = auth_service.get_password_hash(body.password)
    new_user = await rep_users.create_user(body, db)
    return new_user


@router.post("/login", response_model=TokenSchema)
async def login(body: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    # тут фiнт вухами -> [OAuth2PasswordRequestForm] працює тiльки з <self.username>, але в нашому випадку в
    # <body.username> буде <email>, оскiльки ми сами його вставляємо у <x-www-form-urlencoded> у поле <username>
    user = await rep_users.get_user_by_email(body.username, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong credentials")
    if not auth_service.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong credentials")
    # Generate JWT
    access_token = await auth_service.create_access_token(data={"sub": user.email, "DB-class": "PSQL"})
    refresh_token = await auth_service.create_refresh_token(data={"sub": user.email})
    await rep_users.update_token(user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.get('/refresh_token', response_model=TokenSchema)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(get_refresh_token),
                        db: AsyncSession = Depends(get_db)):
    token = credentials.credentials
    email = await auth_service.decode_refresh_token(token)
    user = await rep_users.get_user_by_email(email, db)
    if user.refresh_token != token:
        await rep_users.update_token(user, None, db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = await auth_service.create_access_token(data={"sub": email, "DB-class": "PSQL"})
    refresh_token = await auth_service.create_refresh_token(data={"sub": email})
    await rep_users.update_token(user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}