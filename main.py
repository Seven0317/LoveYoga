# -*- coding: utf-8 -*-
# Version : V1.0
# Author  : Seven
# Date    : 2018/9/8 12:47

from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
import os

from flask_login import UserMixin, LoginManager, login_required, login_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Length

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a string'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
                                        os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'
# login_manager(app)

bootstrap = Bootstrap(app)


@app.route("/", methods=["GET", "POST"])
def index():
    return render_template('index.html')


@app.route("/<username>")
def user(username):
    return render_template('user.html', name=username)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String, nullable=True, unique=True)
    password = db.Column(db.String, nullable=True)


class RegisterForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired(message='User name should not be none.'), Length(6, 12, message='Length of user name should be in 6 ~ 12')])
    password = PasswordField('Password', validators=[DataRequired(message='Password should not be none.'), Length(6, 20, message='Length of password should be in 6 ~ 20')])
    confirm = PasswordField('Confirm password', validators=[EqualTo('password', message='Password does not match.')])
    submit = SubmitField('Register')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('User name has been used, please use other name.')


@app.route("/register/", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User()
        user.username = form.username.data
        user.password = form.password.data
        user.id = 1
        db.session.add(user)
        return redirect(url_for('user', username=user.username))
    return render_template('register.html', form=form)


class LoginForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired])
    password = PasswordField('Password', validators=[DataRequired])
    remember_me = BooleanField('Remember me', default=False)
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data)
        if user is not None and user.verify_password(form.password.data):
            # login_user(user, form.remember_me.data)
            return redirect(url_for('user', username=user.username))
    return render_template('login.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/secret")
@login_required
def secret():
    return "Only authenticated users are allowed."


if __name__ == "__main__":
    app.run()