from os import name
from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'OnTheWayToProduction'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(20), unique=True, nullable=False)
  email = db.Column(db.String(120), unique=True, nullable=False)
  password = db.Column(db.String(120), nullable=False)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))


class LoginForm(FlaskForm):
  email = StringField(validators=[InputRequired(),
                                  Length(min=6, max=30)],
                      render_kw={'placeholder': 'Enter your email'})
  password = StringField(validators=[InputRequired(),
                                     Length(min=6, max=20)],
                         render_kw={'placeholder': 'Enter your password'})
  submit = SubmitField("Sign-In")


class RegistrationForm(FlaskForm):
  username = StringField(validators=[InputRequired(),
                                     Length(min=4, max=20)],
                         render_kw={'placeholder': 'Enter your name'})
  email = StringField(validators=[InputRequired(),
                                  Length(min=6, max=30)],
                      render_kw={'placeholder': 'Enter your email'})
  password = StringField(validators=[InputRequired(),
                                     Length(min=6, max=20)],
                         render_kw={'placeholder': 'Enter your password'})
  submit = SubmitField("Sign-Up")

  def validate_username(self, username):
    existing_user_username = User.query.filter_by(
        username=username.data).first()

    if existing_user_username:
      raise ValidationError(
          'That username already exists. Please choose a different one.')


@app.route("/Dashboard", methods=['GET', 'POST'])
@login_required
def Dashboard():
  return render_template('Dashboard.html', name=current_user.username)


@app.route("/", methods=['GET', 'POST'])
def home():
  Registrationform = RegistrationForm()
  if Registrationform.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(
        Registrationform.password.data)
    new_user = User(username=Registrationform.username.data,
                    email=Registrationform.email.data,
                    password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    flash('Account created successfully!', 'success')
    return redirect(url_for('home'))

  Loginform = LoginForm()
  if Loginform.validate_on_submit():
    user = User.query.filter_by(email=Loginform.email.data).first()
    if user and bcrypt.check_password_hash(user.password,
                                           Loginform.password.data):
      login_user(user)
      flash('Login successfully!', 'success')
      return redirect(url_for('Dashboard'))

  return render_template('home.html',
                         Loginform=Loginform,
                         Registrationform=Registrationform)


if __name__ == "__main__":
  app.app_context().push()
  db.create_all()

  app.run(host='0.0.0.0', port=8080, debug=True)
