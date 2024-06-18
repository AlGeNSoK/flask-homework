import pydantic
from pydantic import BaseModel
from typing import Optional, Type


class BaseUser(BaseModel):

    username: str
    password: str

    @pydantic.field_validator("password")
    @classmethod
    def secure_password(cls, value):
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters")
        return value


class CreateUser(BaseUser):

    username: str
    password: str
    email: str


class UpdateUser(BaseUser):

    username: str
    password: str
    new_username: Optional[str] = None
    new_password: Optional[str] = None
    new_email: Optional[str] = None


class DeleteUser(BaseUser):

    username: str
    password: str


class BaseAdvertisement(BaseModel):

    username: str
    password: str


class CreateAdvertisement(BaseAdvertisement):

    username: str
    password: str
    title: str
    description: str


class UpdateAdvertisement(BaseAdvertisement):

    username: str
    password: str
    title: Optional[str] = None
    description: Optional[str] = None


class DeleteAdvertisement(BaseAdvertisement):

    username: str
    password: str


Schema = (Type[CreateUser] | Type[UpdateUser] | Type[DeleteUser] |
          Type[CreateAdvertisement] | Type[UpdateAdvertisement] | Type[DeleteAdvertisement])
