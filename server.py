from flask import Flask, jsonify, request, Response
from flask.views import MethodView
from models import Session, User, Advertisement
from sqlalchemy.exc import IntegrityError
from schema import (CreateUser, UpdateUser, DeleteUser, Schema,
                    CreateAdvertisement, UpdateAdvertisement, DeleteAdvertisement)
import pydantic
import flask_bcrypt


app = Flask("app")
bcrypt = flask_bcrypt.Bcrypt(app)


def hash_password(password: str):
    return bcrypt.generate_password_hash(password.encode()).decode()


def check_password(password: str, hashed_password: str):
    return bcrypt.check_password_hash(password.encode(), hashed_password.encode())


class HttpError(Exception):

    def __init__(self, status_code:int, error_message: str | dict):
        self.status_code = status_code
        self.error_message = error_message


def validate(schema_cls: Schema, json_data: dict):
    try:
        return schema_cls(**json_data).dict(exclude_unset=True)
    except pydantic.ValidationError as err:
        error = err.errors()[0]
        error.pop('ctx', None)
        raise HttpError(409, error)


@app.errorhandler(HttpError)
def error_handler(err: HttpError):
    json_response = jsonify({"error": err.error_message})
    json_response. status_code = err.status_code
    return json_response


@app.before_request
def before_request():
    session = Session()
    request.session = session


@app.after_request
def after_request(response: Response):
    request.session.close()
    return response


def add_user(user: User):
    request.session.add(user)
    try:
        request.session.commit()
    except IntegrityError:
        raise HttpError(400, {'error': 'User already exists'})
    return user


def get_user(user_id):
    user = request.session.get(User, user_id)
    if user is None:
        raise HttpError(404, {'error': 'User not found'})
    return user


def add_advertisement(advertisement: Advertisement):
    request.session.add(advertisement)
    try:
        request.session.commit()
    except IntegrityError:
        raise HttpError(400, {'error': 'The title and description fields must be filled in'})
    return advertisement


def get_advertisement(advertisement_id):
    advertisement = request.session.get(Advertisement, advertisement_id)
    if advertisement is None:
        raise HttpError(404, {'error': 'Advertisement not found'})
    return advertisement


class UserView(MethodView):

    @property
    def session(self) -> Session:
        return request.session

    def get(self, user_id):
        user = get_user(user_id)
        return jsonify(user.json)

    def post(self):
        json_data = validate(CreateUser, request.json)
        json_data["password"] = hash_password(json_data["password"])
        user = add_user(User(**json_data))
        return jsonify(user.json)

    def patch(self, user_id):
        json_data = validate(UpdateUser, request.json)
        user = get_user(user_id)
        if user.username == json_data["username"] and check_password(user.password, json_data["password"]):
            if "new_username" in json_data:
                user.username = json_data["new_username"]
            if "new_password" in json_data:
                user.password = hash_password(json_data["new_password"])
            if "new_email" in json_data:
                user.email = json_data["new_email"]
            user = add_user(user)
        else:
            raise HttpError(401, {'error': 'Incorrect username or password'})
        return jsonify(user.json)

    def delete(self, user_id):
        json_data = validate(DeleteUser, request.json)
        user = get_user(user_id)
        if user.username == json_data["username"] and check_password(user.password, json_data["password"]):
            self.session.delete(user)
            self.session.commit()
            return jsonify({"status": "User deleted"})
        else:
            raise HttpError(401, {'error': 'Incorrect username or password'})


class AdvertisementView(MethodView):

    @property
    def session(self) -> Session:
        return request.session

    def get(self, advertisement_id):
        advertisement = get_advertisement(advertisement_id)
        return jsonify(advertisement.json)

    def post(self):
        json_data = validate(CreateAdvertisement, request.json)
        user = self.session.query(User).filter_by(username=json_data["username"]).first()
        if user is None:
            raise HttpError(404, {'error': 'User not found'})
        if check_password(user.password, json_data["password"]):
            json_data["owner"] = user.id
            json_data.pop("username", None)
            json_data.pop("password", None)
            advertisement = add_advertisement(Advertisement(**json_data))
            return jsonify(advertisement.json)
        raise HttpError(401, {'error': 'Invalid password'})

    def patch(self, advertisement_id):
        json_data = validate(UpdateAdvertisement, request.json)
        advertisement = get_advertisement(advertisement_id)
        user = self.session.query(User).filter_by(username=json_data["username"]).first()
        if user is None:
            raise HttpError(404, {'error': 'User not found'})
        if check_password(user.password, json_data["password"]):
            if user.id == advertisement.owner:
                json_data.pop("username", None)
                json_data.pop("password", None)
                for field, value in json_data.items():
                    setattr(advertisement, field, value)
                advertisement = add_advertisement(advertisement)
                return jsonify(advertisement.json)
            else:
                raise HttpError(403, {'error': 'Access denied'})
        raise HttpError(401, {'error': 'Invalid password'})

    def delete(self, advertisement_id):
        json_data = validate(DeleteAdvertisement, request.json)
        advertisement = get_advertisement(advertisement_id)
        user = self.session.query(User).filter_by(username=json_data["username"]).first()
        if user is None:
            raise HttpError(404, {'error': 'User not found'})
        if check_password(user.password, json_data["password"]):
            if user.id == advertisement.owner:
                self.session.delete(advertisement)
                self.session.commit()
                return jsonify({"status": "Advertisement deleted"})
            else:
                raise HttpError(403, {'error': 'Access denied'})
        raise HttpError(401, {'error': 'Invalid password'})


user_view = UserView.as_view("user")
advertisement_view = AdvertisementView.as_view("advertisement")

app.add_url_rule('/user/', view_func=user_view, methods=['POST'])
app.add_url_rule('/user/<int:user_id>', view_func=user_view, methods=['GET', 'PATCH', 'DELETE'])

app.add_url_rule('/advertisement/', view_func=advertisement_view, methods=['POST'])
app.add_url_rule('/advertisement/<int:advertisement_id>', view_func=advertisement_view,
                 methods=['GET', 'PATCH', 'DELETE'])

app.run()
