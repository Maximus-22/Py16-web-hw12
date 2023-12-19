from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


from src.database.db import get_db
from src.routes import auth
from src.routes import contacts
from src.routes import search_contacts
from src.routes import birthday_contacts

# Запуск проекту:
# uvicorn main:app --host localhost --port 8000 --reload
# де <app> - це змiнна з наступного рядка!
app = FastAPI()

# routed [auth] розташовується вище за всiх
app.include_router(auth.router, prefix="/api")
app.include_router(contacts.router, prefix="/api")
app.include_router(search_contacts.router, prefix='/api')
app.include_router(birthday_contacts.router, prefix='/api')


@app.get("/")
def index():
    return {"message": "Contacts Application"}


@app.get("/api/healthchecker")
async def healthchecker(db: AsyncSession = Depends(get_db)):
    try:
        # Make request
        result = await db.execute(text(str("SELECT 1")))
        result = result.fetchone()
        if result is None:
            raise HTTPException(status_code=500, detail="Database is not configured correctly")
        return {"message": "Welcome to FastAPI!"}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Error connecting to the database")