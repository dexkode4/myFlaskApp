import os
import requests
from flask import request, current_app
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import create_refresh_token, get_jwt_identity, create_access_token, get_jwt
from flask_jwt_extended import jwt_required
from sqlalchemy.exc import SQLAlchemyError
import traceback
import sys

from blocklist import BLOCKLIST
from db import db
from models import UserModel
from schemas import UserSchema, UserLoginSchema

blp = Blueprint("Users", __name__, description="Operations on users")


def send_simple_message(to, subject, body):
  	return requests.post(
  		"https://api.mailgun.net/v3/sandbox76c97931eee1438ebbf719dfa16005ef.mailgun.org/messages",
  		auth=("api", os.getenv('MAILGUN_API_KEY')),
  		data={"from": "STORE API <postmaster@sandbox76c97931eee1438ebbf719dfa16005ef.mailgun.org>",
			"to": [to],
  			"subject": subject,
  			"text": body})

@blp.route("/register")                  
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        # Validate required fields first
        if not user_data.get("username"):
            abort(400, message="Username is required")
        if not user_data.get("email"):
            abort(400, message="Email is required")
        if not user_data.get("password"):
            abort(400, message="Password is required")
            
        current_app.logger.info(f"Attempting to register user with username: {user_data.get('username')}")
        
        # Check for existing username
        if UserModel.query.filter(UserModel.username == user_data["username"]).first():
            current_app.logger.warning(f"Registration failed: Username '{user_data['username']}' already exists")
            abort(409, message=f"Username '{user_data['username']}' is already taken. Please choose a different username.")
        
        # Check for existing email
        if UserModel.query.filter(UserModel.email == user_data["email"]).first():
            current_app.logger.warning(f"Registration failed: Email '{user_data['email']}' is already registered")
            abort(409, message=f"Email '{user_data['email']}' is already registered. Please use a different email address.")
            
        try:
            user = UserModel(
                username=user_data["username"],
                email=user_data["email"],
                password=pbkdf2_sha256.hash(user_data["password"])
            )
            current_app.logger.info("User model created successfully")
            
            db.session.add(user)
            current_app.logger.info("User added to session")
            
            db.session.commit()
            current_app.logger.info("User committed to database successfully")
            
            send_simple_message(
                to=user.email,
                subject="Successfully signed up",
                body=f"Hi {user.username}! You have successfully signed up to the store REST API."
                )
            return {"message": "User created successfully."}, 201
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error during user registration: {str(e)}")
            current_app.logger.error(traceback.format_exc())
            abort(500, message=f"Database error during registration: {str(e)}")
        except Exception as e:
            current_app.logger.error(f"Unexpected error during registration: {str(e)}")
            current_app.logger.error(f"Error type: {type(e).__name__}")
            current_app.logger.error(traceback.format_exc())
            
            if isinstance(e, SQLAlchemyError):
                db.session.rollback()
                abort(500, message=f"Database error during registration: {str(e)}")
            else:
                abort(500, message=f"An unexpected error occurred during registration. Please try again later.")

@blp.route("/user/<int:user_id>")
class User(MethodView):
    @blp.response(200, UserSchema)
    def get(self, user_id):
        try:
            user = UserModel.query.get_or_404(user_id)
            return user
        except Exception as e:
            abort(500, message=f"An error occurred while retrieving user: {str(e)}")

    def delete(self, user_id):
        try:
            user = UserModel.query.get_or_404(user_id)
            try:
                db.session.delete(user)
                db.session.commit()  
                return {"message": "User deleted."}, 200
            except SQLAlchemyError as e:
                abort(500, message=f"An error occurred while deleting user: {str(e)}")
        except Exception as e:
            abort(500, message=f"An error occurred during deletion: {str(e)}")

@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserLoginSchema)
    def post(self, user_data):
        try:
            # Check if either username or email is provided
            if not user_data.get("username") and not user_data.get("email"):
                abort(400, message="Either username or email is required.")
            
            # Try to find user by username or email
            if user_data.get("username"):
                user = UserModel.query.filter(
                    UserModel.username == user_data["username"]
                ).first()
            else:
                user = UserModel.query.filter(
                    UserModel.email == user_data["email"]
                ).first()

            if user and pbkdf2_sha256.verify(user_data["password"], user.password):
                access_token = create_access_token(identity=str(user.id), fresh=True)
                refresh_token = create_refresh_token(identity=str(user.id))
                return {"access_token": access_token, "refresh_token": refresh_token}
            
            abort(401, message="Invalid credentials")
        except Exception as e:
            abort(500, message=f"An error occurred during login: {str(e)}")

@blp.route("/logout")
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        try:
            jti = get_jwt()["jti"]
            BLOCKLIST.add(jti)
            return {"message": "Successfully logged out"}
        except Exception as e:
            abort(500, message=f"An error occurred during logout: {str(e)}")

@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required()
    def post(self):
        try:
            current_user = get_jwt_identity()
            new_token = create_access_token(identity=current_user, fresh=False)
            jti = get_jwt()["jti"]
            BLOCKLIST.add(jti)
            return {"access_token": new_token}
        except Exception as e:
            abort(500, message=f"An error occurred during token refresh: {str(e)}")