import enum
from datetime import date

from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, ForeignKey, DateTime, func, Enum
from sqlalchemy.orm import DeclarativeBase

from sqlalchemy import Column, Integer, String, Date, ForeignKey, DateTime, func, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class Contact(Base):
    __tablename__ = 'contacts'

    id = Column(Integer, primary_key=True)
    first_name = Column(String(32), nullable=False, index=True)
    last_name = Column(String(32), nullable=False, index=True)
    email = Column(String(64), unique=True, nullable=False, index=True)
    phone_number = Column(String(24), nullable=False, index=True)
    birth_date = Column(Date, nullable=False, index=True)
    crm_status = Column(String, default='operational')
    created_at: Mapped[date] = mapped_column('created_at', DateTime, default=func.now(), nullable=True)
    updated_at: Mapped[date] = mapped_column('updated_at', DateTime, default=func.now(), onupdate=func.now(),
                                             nullable=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=True)
    user: Mapped["User"] = relationship("User", backref="contacts", lazy="joined")


class Role(enum.Enum):
    admin: str = "admin"
    moderator: str = "moderator"
    user: str = "user"


class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50))
    email: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    # цей [Enum] з [sqlalchemy], але з ним буде проблема при мiграцiї:
    # -> пiсля створення мiграцiї потрiбно зайти у її файл та прописати що потрiбно створити новий переличений
    # тип даних у БД, а також надати iнструкцiю що робити при зворотньому вiдкатi...
    role: Mapped[Enum] = mapped_column('role', Enum(Role), default=Role.user, nullable=True)
    avatar: Mapped[str] = mapped_column(String(255), nullable=True)
    refresh_token: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[date] = mapped_column('created_at', DateTime, default=func.now())
    updated_at: Mapped[date] = mapped_column('updated_at', DateTime, default=func.now(), onupdate=func.now())
