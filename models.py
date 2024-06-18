import os
import datetime
from atexit import register

from sqlalchemy import create_engine, Integer, String, DateTime, func, ForeignKey
from sqlalchemy.orm import sessionmaker, DeclarativeBase, mapped_column, Mapped


POSTGRES_USER = os.getenv('POSTGRES_USER', "user")
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', "pas1234/")
POSTGRES_DB = os.getenv('POSTGRES_DB', "homework_flask")
POSTGRES_HOST = os.getenv('POSTGRES_HOST', "127.0.0.1")
POSTGRES_PORT = os.getenv('POSTGRES_PORT', "5555")


engine = create_engine(f"postgresql://"
                       f"{POSTGRES_USER}:{POSTGRES_PASSWORD}@"
                       f"{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}")

Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(72), nullable=False)
    email: Mapped[str] = mapped_column(String(64), unique=True)

    @property
    def json(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email
        }


class Advertisement(Base):
    __tablename__ = 'advertisements'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    created_time: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())
    owner: Mapped[int] = mapped_column(ForeignKey('users.id'))

    @property
    def json(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "created_time": self.created_time.isoformat(),
            "owner": self.owner,
        }


Base.metadata.create_all(engine)
register(engine.dispose)
