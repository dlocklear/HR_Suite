from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField, TextAreaField, DateField
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
    
class PersonalActionForm(FlaskForm):
    transaction_codes = SelectField('Transaction Codes', choices=[
        ('transfer', 'Transfer'), ('hire', 'Hire'), ('pay_rate_change', 'Pay Rate Change'), 
        ('promotion', 'Promotion'), ('demotion', 'Demotion'), ('status_change', 'Status Change'), 
        ('leave_of_absence', 'Leave of Absence'), ('paid_leave_of_absence', 'Paid Leave of Absence'), 
        ('termination', 'Termination'), ('termination_with_pay', 'Termination With Pay'), 
        ('retirement', 'Retirement'), ('data_change', 'Data Change'), ('return_from_leave', 'Return From Leave')], validators=[DataRequired()])
    
    reason_codes = SelectField('Reason Codes', choices=[
        ('reason1', 'Reason 1'), ('reason2', 'Reason 2'), ('reason3', 'Reason 3')], validators=[DataRequired()])

    position_title = StringField('Position Title', validators=[DataRequired()])
    position_id = StringField('Position ID', validators=[DataRequired()])
    dept_cost_ctr = StringField('Dept/Cost Ctr', validators=[DataRequired()])
    supervisor_name = StringField('Supervisor Name', validators=[DataRequired()])
    supervisor_position = StringField('Supervisor Position', validators=[DataRequired()])
    pay_group = StringField('Pay Group', validators=[DataRequired()])
    org_code = StringField('Org Code', validators=[DataRequired()])
    hay_band = StringField('Hay Band', validators=[DataRequired()])
    yearly_salary = StringField('Yearly Salary', validators=[DataRequired()])
    hourly_rate = StringField('Hourly Rate', validators=[DataRequired()])
    std_eligibility = StringField('STD Eligibility', validators=[DataRequired()])
    
    weeks_full_pay = StringField('Weeks Full Pay', validators=[DataRequired()])
    weeks_60_pay = StringField('Weeks 60% Pay', validators=[DataRequired()])
    pay_through = StringField('Pay Through', validators=[DataRequired()])

    additional_payments_due_employee = StringField('Additional Payments Due Employee', validators=[DataRequired()])
    effective_date = DateField('Effective Date', format='%Y-%m-%d', validators=[DataRequired()])
    employee_name = StringField('Employee Name', validators=[DataRequired()])
    full_address = TextAreaField('Full Address', validators=[DataRequired()])
    associate_id = StringField('Associate ID', validators=[DataRequired()])

    current_position_title = StringField('Current Position Title', validators=[DataRequired()])
    new_position_title = StringField('New Position Title', validators=[DataRequired()])
    current_dept_cost_ctr = StringField('Current Dept/Cost Ctr', validators=[DataRequired()])
    new_dept_cost_ctr = StringField('New Dept/Cost Ctr', validators=[DataRequired()])
    current_supervisor_name = StringField('Current Supervisor Name', validators=[DataRequired()])
    new_supervisor_name = StringField('New Supervisor Name', validators=[DataRequired()])
    current_supervisor_position = StringField('Current Supervisor Position', validators=[DataRequired()])
    new_supervisor_position = StringField('New Supervisor Position', validators=[DataRequired()])
    current_pay_group = StringField('Current Pay Group', validators=[DataRequired()])
    new_pay_group = StringField('New Pay Group', validators=[DataRequired()])
    current_org_code = StringField('Current Org Code', validators=[DataRequired()])
    new_org_code = StringField('New Org Code', validators=[DataRequired()])
    current_hay_band = StringField('Current Hay Band', validators=[DataRequired()])
    new_hay_band = StringField('New Hay Band', validators=[DataRequired()])
    current_yearly_salary = StringField('Current Yearly Salary', validators=[DataRequired()])
    new_yearly_salary = StringField('New Yearly Salary', validators=[DataRequired()])
    current_hourly_rate = StringField('Current Hourly Rate', validators=[DataRequired()])
    new_hourly_rate = StringField('New Hourly Rate', validators=[DataRequired()])

    special_instructions = TextAreaField('Special Instructions', validators=[DataRequired()])
    approver = StringField('Approver', validators=[DataRequired()])

    submit = SubmitField('Submit')
    
class LeaveRequestForm(FlaskForm):
    employee_name = StringField('Employee Name', validators=[DataRequired()])
    employee_id = StringField('Employee ID', validators=[DataRequired()])
    leave_type = SelectField('Leave Type', choices=[('sick', 'Sick Leave'), ('vacation', 'Vacation'), ('personal', 'Personal')], validators=[DataRequired()])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[DataRequired()])
    submit = SubmitField('Submit')

class PersonalLeaveForm(FlaskForm):
    employee_name = StringField('Employee Name', validators=[DataRequired()])
    employee_id = StringField('Employee ID', validators=[DataRequired()])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[DataRequired()])
    submit = SubmitField('Submit')

class AnonymousComplaintForm(FlaskForm):
    complaint_type = SelectField('Complaint Type', choices=[('harassment', 'Harassment'), ('discrimination', 'Discrimination'), ('safety', 'Safety')], validators=[DataRequired()])
    details = TextAreaField('Details', validators=[DataRequired()])
    submit = SubmitField('Submit')
