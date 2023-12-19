from fastapi import APIRouter, HTTPException, Depends, status, Path, Query
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.db import get_db
from src.repository import contacts as rep_contacts
from src.schemas.contact import ContactSchema, ContactUpdateSchema, ContactResponseSchema
from src.entity.models import User, Role
from src.services.auth import auth_service
from src.services.roles import RoleAccess

router = APIRouter(prefix='/search', tags=['search'])

# Цей функтор буде пропускати тiльки тi запити, ролi в користувачiв яких спiвпадають
access_elevated = RoleAccess([Role.admin, Role.moderator])


""" У цьому місці реалізовано опціональний вибір пошуку по одному з полів - за кожне поле
    відповідає окрема функція """
# @router.get("/", response_model=list[ContactResponseSchema])
# async def search_contact_by_field(
#     first_name: Optional[str] = Query(None, description="Ім'я контакту"),
#     last_name: Optional[str] = Query(None, description="Прізвище контакту"),
#     email: Optional[str] = Query(None, description="Електронна адреса контакту"),
#     db: AsyncSession = Depends(get_db)):
#     if first_name:
#         return await rep_contacts.search_contact_by_firstname(first_name, db)
#     elif last_name:
#         return await rep_contacts.search_contact_by_lastname(last_name, db)
#     elif email:
#         return await rep_contacts.search_contact_by_email(email, db)
#     else:
#         raise ValueError("Необхідно вказати: ім'я, прізвище або e-mail контакту.")


""" У цьому випадку Path(..., <default>, <title>, <description>) означає, що параметр
    <contact_first_name> є обов'язковим і повинен бути вказаний в [URL]. Якщо параметр не вказано,
    буде викликано виняток. """
@router.get("/by_firstname/{contact_first_name}", response_model=list[ContactResponseSchema])
async def search_contact_by_firstname(contact_first_name: str = Path(..., description="Ім'я контакту"),
                              db: AsyncSession = Depends(get_db), user: User = Depends(auth_service.get_current_user)):
    contacts = await rep_contacts.search_contact_by_firstname(contact_first_name, db)
    return contacts

@router.get("/by_lastname/{contact_last_name}", response_model=list[ContactResponseSchema])
async def search_contact_by_lastname(contact_last_name: str = Path(..., description="Прізвище контакту"),
                              db: AsyncSession = Depends(get_db), user: User = Depends(auth_service.get_current_user)):
    contacts = await rep_contacts.search_contact_by_lastname(contact_last_name, db)
    return contacts

@router.get("/by_email/{contact_email}", response_model=list[ContactResponseSchema])
async def search_contact_by_email(contact_email: str = Path(..., description="Електронна адреса контакту"),
                              db: AsyncSession = Depends(get_db), user: User = Depends(auth_service.get_current_user)):
    contacts = await rep_contacts.search_contact_by_email(contact_email, db)
    return contacts


# Знайдена міцна залежність між шляхом {value} та назвою змінної у функції -> search_contact_complex(value, ... 
@router.get("/by_complex/{value}", response_model=list[ContactResponseSchema], dependencies=[Depends(access_elevated)])
async def search_contact_complex(value: str = Path(..., description="Здійснює пошук у полях контакту: Ім'я, Прізвище та Електронна адреса"),
                              db: AsyncSession = Depends(get_db), user: User = Depends(auth_service.get_current_user)):
    contacts = await rep_contacts.search_contact_complex(value, db)
    return contacts