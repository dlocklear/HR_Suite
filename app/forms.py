from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    SelectField,
    TextAreaField,
    DateField,
    SubmitField,
    HiddenField,
    PasswordField,
    DecimalField,
    FloatField,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, InputRequired, number_range


class RegistrationForm(FlaskForm):
    name = StringField("Name", validators=[
                       DataRequired(), Length(min=2, max=50)])
    user_id = StringField("User ID", validators=[DataRequired()])
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=2, max=20)]
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[
                             DataRequired(), Length(min=6)])
    current_salary = StringField("Current Salary", validators=[
        DataRequired()])
    pay_grade = SelectField(
        "Pay Grade",
        choices=[("e0", "E0"), ("e1", "E1"), ("e2", "E2"), ("e3", "E3"), ("e4", "E4"),
                 ("e5", "E5"), ("e6", "E6"), ("e7", "E7"), ("e8", "E8"), ("e9", "E9"), ("e10", "E10")],
        validators=[DataRequired()],
    )
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    role = SelectField(
        "Role",
        choices=[("user", "User"), ("manager", "Manager"), ("admin", "Admin")],
        validators=[DataRequired()],
    )
    flsa_code = SelectField(
        "FLSA Code",
        choices=[("exempt", "Exempt"), ("non-exempt", "non-Exempt")],
        validators=[DataRequired()],
    )
    worker_category = SelectField(
        "Worker Category",
        choices=[("full time", "Full Time"), ("part time", "Part Time")],
        validators=[DataRequired()],
    )
    employee_id = StringField("Employee ID", validators=[DataRequired()])
    title = StringField("Title", validators=[DataRequired()])
    reports_to = StringField("Reports To", validators=[DataRequired()])
    position_id = StringField("Position ID", validators=[DataRequired()])
    hire_date = DateField("Hire Date", format="%Y-%m-%d",
                          validators=[DataRequired()])
    effective_date = DateField("Effective Date", format="%Y-%m-%d",
                               validators=[DataRequired()])
    created_at = DateField("Created At", format="%Y-%m-%d",
                           validators=[DataRequired()])
    updated_at = DateField("Updated At", format="%Y-%m-%d",
                           validators=[DataRequired()])
    seniority_date = DateField(
        "Seniority Date", format="%Y-%m-%d", validators=[DataRequired()]
    )
    department = StringField("Department", validators=[DataRequired()])
    status = SelectField(
        "Status",
        choices=[("active", "Active"), ("inactive", "Inactive")],
        validators=[DataRequired()],
    )
    company_code = SelectField('Company code', choices=[(
        'F6I', 'F6I'), ('WYH', 'WYH')], validators=[DataRequired()])
    submit = SubmitField("Register")


class PasswordResetForm(FlaskForm):
    user_email = StringField("Email", validators=[DataRequired(), Email()])
    new_password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("new_password")]
    )
    submit = SubmitField("Reset Password")


class UploadForm(FlaskForm):
    file = StringField("File", validators=[DataRequired()])
    submit = SubmitField("Upload")


class PersonalActionForm(FlaskForm):
    transaction_codes = SelectField(
        "Transaction Codes",
        choices=[
            ("transfer", "Transfer"),
            ("hire", "Hire"),
            ("pay_rate_change", "Pay Rate Change"),
            ("promotion", "Promotion"),
            ("demotion", "Demotion"),
            ("status_change", "Status Change"),
            ("termination", "Termination"),
            ("termination_with_pay", "Termination With Pay"),
            ("retirement", "Retirement"),
            ("data_change", "Data Change"),
        ],
        validators=[DataRequired()],
    )

    reason_codes = SelectField(
        "Reason Codes",
        choices=[
            ("reason1", "Reason 1"),
            ("reason2", "Reason 2"),
            ("reason3", "Reason 3"),
        ],
        validators=[DataRequired()],
    )

    employee_name = StringField("Employee Name", validators=[DataRequired()])
    employee_id = HiddenField("Employee ID")
    effective_date = DateField(
        "Effective Date", format="%Y-%m-%d", validators=[DataRequired()]
    )

    position_title = StringField("Position Title", validators=[DataRequired()])
    position_id = StringField("Position ID", validators=[DataRequired()])
    department = StringField("Department", validators=[DataRequired()])
    company_code = StringField("Company Code", validators=[DataRequired()])
    pay_grade = StringField("Pay Grade", validators=[DataRequired()])
    supervisor_name = StringField(
        "Supervisor Name", validators=[DataRequired()])
    supervisor_position = StringField(
        "Supervisor Position", validators=[DataRequired()]
    )

    current_position_title = StringField(
        "Current Position Title", validators=[DataRequired()]
    )
    new_position_title = StringField(
        "New Position Title", validators=[DataRequired()])
    current_department = StringField(
        "Current Department", validators=[DataRequired()])
    new_department = StringField("New Department", validators=[DataRequired()])
    current_supervisor_name = StringField(
        "Current Supervisor Name", validators=[DataRequired()]
    )
    new_supervisor_name = StringField(
        "New Supervisor Name", validators=[DataRequired()]
    )
    current_supervisor_position = StringField(
        "Current Supervisor Position", validators=[DataRequired()]
    )
    new_supervisor_position = StringField(
        "New Supervisor Position", validators=[DataRequired()]
    )
    current_pay_group = StringField(
        "Current Pay Group", validators=[DataRequired()])
    new_pay_group = StringField("New Pay Group", validators=[DataRequired()])
    current_pay_grade = StringField(
        "Current Pay Grade", validators=[DataRequired()])
    new_pay_grade = StringField("New Pay Grade", validators=[DataRequired()])
    current_yearly_salary = StringField(
        "Current Yearly Salary", validators=[DataRequired()]
    )
    new_yearly_salary = StringField(
        "New Yearly Salary", validators=[DataRequired()])
    current_hourly_rate = StringField(
        "Current Hourly Rate", validators=[DataRequired()]
    )
    new_hourly_rate = StringField(
        "New Hourly Rate", validators=[DataRequired()])

    weeks_full_pay = StringField("Weeks Full Pay", validators=[DataRequired()])
    weeks_60_pay = StringField("Weeks 60% Pay", validators=[DataRequired()])
    pay_through = DateField(
        "Pay Through", format="%Y-%m-%d", validators=[DataRequired()]
    )
    additional_payments_due_employee = StringField(
        "Additional Payments Due Employee", validators=[DataRequired()]
    )

    special_instructions = TextAreaField(
        "Special Instructions", validators=[DataRequired()]
    )
    approver = StringField("Approver", validators=[DataRequired()])

    submit = SubmitField("Submit")


class LeaveRequestForm(FlaskForm):
    employee_name = StringField("Employee Name", validators=[DataRequired()])
    employee_id = StringField("Employee ID", validators=[DataRequired()])
    leave_type = SelectField(
        "Leave Type",
        choices=[("sick", "Sick"), ("vacation", "Vacation"),
                 ("personal", "Personal")],
        validators=[DataRequired()],
    )
    start_date = DateField("Start Date", format="%Y-%m-%d",
                           validators=[DataRequired()])
    end_date = DateField("End Date", format="%Y-%m-%d",
                         validators=[DataRequired()])
    reason = TextAreaField("Reason", validators=[DataRequired()])
    submit = SubmitField("Submit")


class PersonalLeaveForm(FlaskForm):
    employee_name = StringField("Employee Name", validators=[DataRequired()])
    employee_id = StringField("Employee ID", validators=[DataRequired()])
    start_date = DateField("Start Date", format="%Y-%m-%d",
                           validators=[DataRequired()])
    end_date = DateField("End Date", format="%Y-%m-%d",
                         validators=[DataRequired()])
    reason = TextAreaField("Reason", validators=[DataRequired()])
    submit = SubmitField("Submit")


class AnonymousComplaintForm(FlaskForm):
    complaint_type = SelectField(
        "Complaint Type",
        choices=[
            ("harassment", "Harassment"),
            ("discrimination", "Discrimination"),
            ("other", "Other"),
        ],
        validators=[DataRequired()],
    )
    details = TextAreaField("Details", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Form class


class PerformanceEvaluationForm(FlaskForm):
    employee_id = SelectField('Employee', validators=[InputRequired()])
    business_result = DecimalField('Business Result (%)', validators=[
                                   InputRequired(), NumberRange(min=0, max=100)])
    individual_result = DecimalField('Individual Result (%)', validators=[
                                     InputRequired(), NumberRange(min=0, max=100)])
    safety_result = DecimalField('Safety Result (%)', validators=[
                                 InputRequired(), NumberRange(min=0, max=100)])
    submit = SubmitField('Submit')


class AcceptUserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Accept Invitation')


class CreateUserForm(FlaskForm):
    employee_id = StringField('Employee ID', validators=[
                              DataRequired(), Length(max=50)])
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=3, max=255)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, max=36),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField(
        'Confirm Password', validators=[DataRequired()])
    email = StringField('Email', validators=[
                        DataRequired(), Email(), Length(max=255)])
    role = SelectField('Role', choices=[
                       ('admin', 'Admin'), ('manager', 'Manager'), ('employee', 'Employee')], validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired(), Length(max=255)])
    status = SelectField('Status', choices=[
                         ('pending', 'Pending'), ('approved', 'Approved')], validators=[DataRequired()])
    submit = SubmitField('Create User')

class NotificationForm(FlaskForm):
    notification_message = StringField('Notification Message', validators=[DataRequired()])
    submit = SubmitField('Start Workflow')