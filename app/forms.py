from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, FileField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_wtf.file import FileAllowed

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    employee_id = StringField('Employee ID', validators=[DataRequired()])
    title = StringField('Title', validators=[DataRequired()])
    reports_to = StringField('Reports To', validators=[DataRequired()])
    position_id = StringField('Position ID', validators=[DataRequired()])
    hire_date = DateField('Hire Date', validators=[DataRequired()])
    seniority_date = DateField('Seniority Date', validators=[DataRequired()])
    department = StringField('Department', validators=[DataRequired()])
    submit = SubmitField('Register')

class PasswordResetForm(FlaskForm):
    user_email = StringField('User Email', validators=[DataRequired(), Email()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')

class UploadForm(FlaskForm):
    file = FileField('Document', validators=[DataRequired(), FileAllowed(['pdf', 'docx', 'csv'], 'Documents only!')])
    submit = SubmitField('Upload')
