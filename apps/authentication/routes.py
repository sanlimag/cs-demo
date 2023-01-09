# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
import sys

from flask import render_template, redirect, request, url_for
from flask_login import (
    current_user,
    login_user,
    logout_user
)

from apps import db, login_manager
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm
from apps.authentication.models import Users
from apps.authentication.util import verify_pass

import json_logging, logging

#Configure logging
json_logging.init_flask(enable_json=True)
logger = logging.getLogger("app-logger")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())
logging.getLogger('werkzeug').setLevel(logging.ERROR)

@blueprint.route('/')
def route_default():
    return redirect(url_for('authentication_blueprint.login'))


# Login & Registration

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:

        # read form data
        username = request.form['username']
        password = request.form['password']

        # Locate user
        user = Users.query.filter_by(username=username).first()

        # Check the password
        if user and verify_pass(password, user.password):

            login_user(user)
            logger.info(f'{{"action": "login", "status": "completed", "parameters": [ "username": {username}, "user_type": "subscriber"]}}')
            return redirect(url_for('authentication_blueprint.route_default'))

        # Something (user or pass) is not ok
        logger.error(f'{{"action": "login", "status": "failed", "reason": "wrong credentials", "parameters": [ "username": {username}, "user_type": "subscriber"]}}')
        return render_template('accounts/login.html',
                               msg='Wrong user or password',
                               form=login_form)

    if not current_user.is_authenticated:
        return render_template('accounts/login.html',
                               form=login_form)
    return redirect(url_for('home_blueprint.index'))


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']

        # Check usename exists
        user = Users.query.filter_by(username=username).first()
        logger.info(f'{{"action": "create_user", "status": "completed", "parameters": [ "username": {username},"user_type": "subscriber"]}}')
        if user:
            logger.error(f'{{"action": "create_user", "status": "failed", "reason": "duplicated username", "parameters": [ "username": {username},"user_type": "subscriber"]}}')
            return render_template('accounts/register.html',
                                   msg='Username already registered',
                                   success=False,
                                   form=create_account_form)

        # Check email exists
        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Email already registered',
                                   success=False,
                                   form=create_account_form)

        # else we can create the user
        user = Users(**request.form)
        db.session.add(user)
        db.session.commit()

        logger.info(f'{{"action": "create_user", "status": "completed", "parameters": [ "username": {username},"user_type": "subscriber"]}}')
        return render_template('accounts/register.html',
                               msg='User created please <a href="/login"><b>login</b></a>',
                               success=True,
                               form=create_account_form)

    else:
        return render_template('accounts/register.html', form=create_account_form)


@blueprint.route('/logout')
def logout():
    logout_user()
    logger.info(f'{{"action": "logout", "status": "completed"}}')
    return redirect(url_for('authentication_blueprint.login'))


# Errors

@login_manager.unauthorized_handler
def unauthorized_handler():
    logger.error(f'{{"action": "get_page", "status": "failed", "reason": "unauthorized handler", "parameters": [ "error": 403]}}')
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    logger.error(f'{{"action": "get_page", "status": "failed", "reason": "unauthorized access attempt", "parameters": [ "error": 403]}}')
    return render_template('home/page-403.html'), 403

@blueprint.errorhandler(404)
def not_found_error(error):
    logger.error(f'{{"action": "get_page", "status": "failed", "reason": "page not found", "parameters": [ "error": 404]}}')
    return render_template('home/page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    logger.error(f'{{"action": "get_page", "status": "failed", "reason": "server/internal error", "parameters": [ "error": 500]}}')
    return render_template('home/page-500.html'), 500
