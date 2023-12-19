from datetime import datetime, timedelta
from fastapi import HTTPException
from sqlalchemy import Date, func, select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.entity.models import Contact, User
from src.schemas.contact import ContactSchema, ContactResponseSchema


async def get_contacts(limit: int, offset: int, db: AsyncSession, user: User):
    # user=user це посиланя на властивiсть класу [Contact] -> Contact.user; оскiльки у функцiю заходить модель User
    # то [sqlalchemy] зрозумiє цю властивiсть через Mapped["User"] = relationship("User", ... 
    # АЛЕ, можна скористатися й таким записом user_id = user.id  
    statement = select(Contact).filter_by(user=user).offset(offset).limit(limit)
    contacts = await db.execute(statement)
    return contacts.scalars().all()


async def get_contacts_all(limit: int, offset: int, db: AsyncSession):
    statement = select(Contact).offset(offset).limit(limit)
    contacts = await db.execute(statement)
    return contacts.scalars().all()


async def get_contact(contact_id: int, db: AsyncSession, user: User):
    statement = select(Contact).filter_by(id=contact_id, user=user)
    contact = await db.execute(statement)
    return contact.scalar_one_or_none()


async def create_contact(body: ContactSchema, db: AsyncSession, user: User):
    # Метод [model_dump()] у Pydantic моделях використовується для перетворення моделі на словник.
    # (first_name=body.first_name, last_name=body.last_name, ...)
    # Параметр <exclude_unset> = True вказує, що в результуючий словник повинні бути включені тільки поля,
    # які були встановлені (тобто не мають значення за замовчуванням).
    contact = Contact(**body.model_dump(exclude_unset=True), user=user)
    db.add(contact)
    await db.commit()
    await db.refresh(contact)
    return contact


async def update_contact(contact_id: int, body: ContactSchema, db: AsyncSession, user: User):
    statement = select(Contact).filter_by(id=contact_id, user=user)
    result = await db.execute(statement)
    contact = result.scalar_one_or_none()
    if contact:
        contact.first_name = body.first_name
        contact.last_name = body.last_name
        contact.email = body.email
        contact.phone_number = body.phone_number
        contact.birth_date = body.birth_date
        contact.crm_status = body.crm_status
        await db.commit()
        await db.refresh(contact)
    return contact


async def delete_contact(contact_id: int, db: AsyncSession, user: User):
    statement = select(Contact).filter_by(id=contact_id, user=user)
    contact = await db.execute(statement)
    contact = contact.scalar_one_or_none()
    if contact:
        await db.delete(contact)
        await db.commit()
    return contact


async def search_contact_by_firstname(contact_first_name: str, db: AsyncSession):
    statement = select(Contact).where(Contact.first_name.ilike(f'%{contact_first_name}%'))
    result = await db.execute(statement)
    if result:
        return result.scalars().all()
    # raise ValueError("204 No Content. The Search did not get results.")
    raise HTTPException(status_code=204, detail="No Content. The Search did not get results.")


async def search_contact_by_lastname(contact_last_name: str, db: AsyncSession):
    statement = select(Contact).where(Contact.last_name.ilike(f'%{contact_last_name}%'))
    result = await db.execute(statement)
    if result:
        return result.scalars().all()
    # raise ValueError("204 No Content. The Search did not get results.")
    raise HTTPException(status_code=204, detail="No Content. The Search did not get results.")


async def search_contact_by_email(contact_email: str, db: AsyncSession):
    statement = select(Contact).where(Contact.email.ilike(f'%{contact_email}%'))
    result = await db.execute(statement)
    if result:
        return result.scalars().all()
    # raise ValueError("204 No Content. The Search did not get results.")
    raise HTTPException(status_code=204, detail="No Content. The Search did not get results.")


async def search_contact_complex(query: str, db: AsyncSession):
    statement = select(Contact).where(or_(
        Contact.first_name.ilike(f'%{query}%'),
        Contact.last_name.ilike(f'%{query}%'),
        Contact.email.ilike(f'%{query}%')
    ))
    result = await db.execute(statement)
    return result.scalars().all()


""" У FastAPI є спеціальні класи і функції для повернення помилок користувача і їх відображення в Swagger.
    Щоб повернути помилку користувача з кодом відповіді <422> (Unprocessable Entity) і відповідним повідомленням,
    можна використати клас [HTTPException] з FastAPI. """

async def search_contact_by_birthdate(forward_shift_days: int, db: AsyncSession):
    if forward_shift_days > 364:
        # raise ValueError("The <forward_shift_days> parameter should be 364 or less.")
        raise HTTPException(status_code=422, detail="The <forward_shift_days> parameter should be 364 or less.")
    current_date = datetime.now().date()
    end_of_shift_date = current_date + timedelta(forward_shift_days)
    # statement = select(Contact).where(between(Contact.birth_date, current_date, end_of_shift_date))
    # statement = select(Contact).where(Contact.birth_date.between(current_date, end_of_shift_date))
    # statement = select(Contact).where(and_(func.extract("month", Contact.birth_date) == current_date.month,
    #                                     func.extract("day", Contact.birth_date) >= current_date.day,
    #                                     func.extract("day", Contact.birth_date) <= end_of_shift_date.day))
    # if current_date.year == end_of_shift_date.year:
    statement = select(Contact).where(or_(
                and_(func.extract("month", Contact.birth_date) == current_date.month,
                    func.extract("day", Contact.birth_date) >= current_date.day,),
                and_(func.extract("month", Contact.birth_date) <= end_of_shift_date.month,
                    func.extract("day", Contact.birth_date) <= end_of_shift_date.day)))

    result = await db.execute(statement)
    if result:
        return result.scalars().all()
    # raise ValueError("204 No Content. The Search did not get results.")
    raise HTTPException(status_code=204, detail="No Content. The Search did not get results.")
