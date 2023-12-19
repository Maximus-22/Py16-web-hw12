from fastapi import APIRouter, HTTPException, Depends, status, Path, Query
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.db import get_db
from src.entity.models import User, Role
from src.repository import contacts as rep_contacts
from src.schemas.contact import ContactSchema, ContactUpdateSchema, ContactResponseSchema
from src.services.auth import auth_service
from src.services.roles import RoleAccess

router = APIRouter(prefix='/birthday', tags=['birthday'])

# Цей функтор буде пропускати тiльки тi запити, ролi в користувачiв яких спiвпадають
access_elevated = RoleAccess([Role.admin, Role.moderator])


# Знайдена міцна залежність між шляхом {shift_days} та назвою змінної у функції -> search_contact_by_birthdate(shift_days, ... 
@router.get("/{shift_days}", response_model=list[ContactResponseSchema], dependencies=[Depends(access_elevated)])
async def search_contact_by_birthdate(shift_days: int = Path(..., description="Кількість найближчих днів у запитi"),
                                      db: AsyncSession = Depends(get_db), user: User = Depends(auth_service.get_current_user)):
    contacts = await rep_contacts.search_contact_by_birthdate(shift_days, db)
    return contacts