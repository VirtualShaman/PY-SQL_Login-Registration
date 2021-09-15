from flask import flash
from flask_app.config.mysqlconnection import connectToMySQL
from flask_app import app

from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


class User:
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']



    @staticmethod
    def validate_register(form_data):
        is_valid = True

        if len(form_data['first_name']) < 2 or len(form_data['first_name']) > 25:
            flash("First name must be between 2 & 25 characters")
            is_valid = False

        if len(form_data['last_name']) < 2 or len(form_data['last_name']) > 25:
            flash("Last name must be between 2 & 25 characters")
            is_valid = False

        if len(form_data['password']) < 8:
            flash("Password must be at least 8 characters long")
            is_valid = False

        if not (form_data['password']) == (form_data['confirm_password']):
            flash("Passwords must match")
            is_valid = False
        if not EMAIL_REGEX.match(form_data['email']):
            flash("Email must be a valid format")
        return is_valid


    @classmethod
    def save(cls, data):
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());"

        results = connectToMySQL('login_and_registration').query_db(query, data)

        return results


    @classmethod
    def get_by_email(cls,data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL("login_and_registration").query_db(query,data)

        if len(result) < 1:
            return False
        return cls(result[0])

    @classmethod
    def get_user_info(cls,data):
        query = "SELECT * FROM users WHERE id = %(user_id)s;"
        result = connectToMySQL("login_and_registration").query_db(query,data)

        return cls(result[0])