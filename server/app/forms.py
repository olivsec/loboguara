from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, TextAreaField, FileField, SelectField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, URL
from flask_wtf.file import FileRequired, FileAllowed
import re
from app.models import Timezone
import os

def password_strength_check(form, field):
    password = field.data
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        raise ValidationError("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValidationError("Password must contain at least one special character.")

def username_check(form, field):
    username = field.data.lower()
    if len(username) < 6:
        raise ValidationError("Username must be at least 6 characters long.")
    if " " in username:
        raise ValidationError("Username cannot contain spaces.")
    if not re.match(r"^[a-zA-Z_][a-zA-Z_0-9]*$", username):
        raise ValidationError("Username must start with a letter and can only contain letters, numbers, and underscores.")
    if username[0] == "_" or username[-1] == "_":
        raise ValidationError("Username cannot start or end with an underscore.")

class LoginForm(FlaskForm):
    username = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

    def validate_username(self, field):
        field.data = field.data.lower()

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=6, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8), EqualTo('confirm_password', message='Passwords must match.')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    timezone = SelectField('Timezone', choices=[], coerce=int)
    is_admin = BooleanField('Admin')
    is_superadmin = BooleanField('Super Admin')
    submit = SubmitField('Register')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timezone.choices = [(tz.id, tz.name) for tz in Timezone.query.all()]


class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

class ResetPasswordTokenForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8),
        password_strength_check,
        EqualTo('confirm_password', message='Passwords must match.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

class KeywordForm(FlaskForm):
    keyword = StringField('Keyword', validators=[DataRequired(), Length(min=5)])
    submit = SubmitField('Add')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=6, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    is_admin = BooleanField('Admin')
    is_superadmin = BooleanField('Super Admin')
    timezone = SelectField('Timezone', choices=[], coerce=int)
    password = PasswordField('New Password', validators=[Length(min=8)])
    confirm = PasswordField('Repeat Password', validators=[EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Update User')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timezone.choices = [(tz.id, tz.name) for tz in Timezone.query.all()]


class VerifyCodeForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired()])
    submit = SubmitField('Verify')

class ImportantNoticesForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()], render_kw={"id": "content"})
    submit = SubmitField('Submit')

class DeleteForm(FlaskForm):
    submit = SubmitField('Delete')
    remove_certificates = BooleanField('Also remove associated certificates')

class UploadForm(FlaskForm):
    dataleak_name = StringField('Data Leak Name', validators=[DataRequired()])
    file = FileField('JSON File', validators=[DataRequired(), FileAllowed(['json'], 'JSON files only!')])
    submit = SubmitField('Upload')

class DataLeakForm(FlaskForm):
    data_leak_name = StringField('Data Leak Name', validators=[DataRequired()])
    json_file = FileField('JSON File', validators=[FileRequired(), FileAllowed(['json'], 'JSON files only!')])
    submit = SubmitField('Upload')

class DomainScanForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    alert_enabled = BooleanField('Enable Email Alert')
    submit = SubmitField('Start Scan')

class URLScanForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired(), URL()])
    alert_enabled = BooleanField('Enable Email Alert')
    submit = SubmitField('Start Scanning')

class URLMonitoringForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired(), URL()])
    scan_interval = StringField('', default=600)
    submit = SubmitField('Start Monitoring')

    def validate_scan_interval(self, field):
        try:
            interval = int(field.data)
            if interval < 300:
                raise ValidationError('The monitoring interval must be at least 300 seconds (5 minutes).')
        except ValueError:
            raise ValidationError('Please enter a valid number for the monitoring interval.')

class WebPathScanForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired(), URL()])
    alert_enabled = BooleanField('Enable Alerts')
    wordlist = SelectField('Select Wordlist', choices=[])
    submit = SubmitField('Start Scan')

    def __init__(self, *args, **kwargs):
        super(WebPathScanForm, self).__init__(*args, **kwargs)
        wordlist_dir = '/opt/loboguara/wordlists/Web-Content'
        wordlist_files = []
        for root, dirs, files in os.walk(wordlist_dir):
            for file in files:
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, wordlist_dir)
                wordlist_files.append((relative_path, relative_path))
        
        self.wordlist.choices = wordlist_files 

class DomainForm(FlaskForm):
    common_name = StringField('Common Name', validators=[DataRequired(), Length(min=5)])
    submit = SubmitField('Add Domain')

class AlertForm(FlaskForm):
    email_alert = BooleanField('Enable Email Alert')
    submit = SubmitField('Save Alert Settings')

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=6, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    is_admin = BooleanField('Admin')
    is_superadmin = BooleanField('Super Admin')
    timezone = SelectField('Timezone', choices=[], coerce=int)
    password = PasswordField('New Password', validators=[
        Length(min=8, message="Password must be at least 8 characters long."),
        EqualTo('confirm', message='Passwords must match.')
    ])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Update User')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timezone.choices = [(tz.id, tz.name) for tz in Timezone.query.all()]

class SearchLeakedDataForm(FlaskForm):
    query = StringField('Search', validators=[DataRequired(), Length(min=5)])
    field = SelectField('Field', choices=[('url', 'URL'), ('username', 'Username'), ('password', 'Password')], validators=[DataRequired()])
    submit = SubmitField('Search')

class UpdateEmailForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Email')

class UpdatePasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        EqualTo('confirm', message='Passwords must match.')
    ])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Update Password')

class UpdateTimezoneForm(FlaskForm):
    timezone = SelectField('Timezone', choices=[], coerce=int)
    submit_timezone = SubmitField('Update Timezone')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timezone.choices = [(tz.id, tz.name) for tz in Timezone.query.all()]

class UpdatePermissionsForm(FlaskForm):
    is_admin = BooleanField('Admin')
    is_superadmin = BooleanField('Super Admin')
    submit_permissions = SubmitField('Update Permissions')


class RedirectionForm(FlaskForm):
    original_url = StringField('Target URL', validators=[DataRequired(), URL()])
    domain = SelectField('Domain', validators=[DataRequired()])
    submit = SubmitField('Generate Tracking Link')
