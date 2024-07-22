import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from supabase import create_client
from app.forms import RegistrationForm, PasswordResetForm, UploadForm, PersonalActionForm, LeaveRequestForm, PersonalLeaveForm, AnonymousComplaintForm
from app import bcrypt
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from werkzeug.utils import secure_filename
import os
import base64
import uuid
import io
import traceback
import json

logging.basicConfig(level=logging.DEBUG)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'docx', 'csv'}

def init_routes(app):
    @app.route('/')
    def index():
        if 'user' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']

            response = app.supabase.auth.sign_in_with_password(
                {"email": email, "password": password})

            if response.user:
                user_data = app.supabase.table('users').select(
                    'role').eq('auth_user_id', response.user.id).execute()
                session['user'] = {
                    'id': response.user.id,
                    'email': response.user.email,
                    'role': user_data.data[0]['role']
                }
                return redirect(url_for('dashboard'))
            else:
                error_message = response.error.message if response.error else "Login failed."
                flash(error_message)

        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(
                form.password.data).decode('utf-8')
            response = app.supabase.auth.sign_up({
                'email': form.email.data,
                'password': form.password.data,
            })
            if response.user:
                app.supabase.table('users').insert({
                    'name': form.name.data,
                    'email': form.email.data,
                    'password': hashed_password,
                    'status': 'pending',
                    'auth_user_id': response.user.id
                }).execute()

                app.supabase.table('employees').insert({
                    'employee_name': form.name.data,
                    'email': form.email.data,
                    'auth_user_id': response.user.id,
                    'employee_id': form.employee_id.data,
                    'title': form.title.data,
                    'reports_to': form.reports_to.data,
                    'position_id': form.position_id.data,
                    'hire_date': form.hire_date.data,
                    'seniority_date': form.seniority_date.data,
                    'department': form.department.data,
                    'company_code': form.company_code.data,
                    'pay_grade': form.pay_grade.data
                }).execute()

                message = Mail(
                    from_email=app.config['FROM_EMAIL'],
                    to_emails=form.email.data,
                    subject='Welcome to HR Suite',
                    html_content='<strong>Your account has been created! Wait for admin approval.</strong>'
                )
                try:
                    sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
                    sg.send(message)
                except Exception as e:
                    print(e.message)

                flash(
                    'Your account has been created! Wait for admin approval.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Registration failed. Please try again.', 'danger')
        return render_template('register.html', form=form)

    @app.route('/dashboard')
    def dashboard():
        if 'user' not in session:
            flash('You need to be logged in to view the dashboard.')
            return redirect(url_for('login'))
        return render_template('dashboard.html')

    @app.route('/logout')
    def logout():
        session.pop('user', None)
        flash("You have successfully logged out.")
        return redirect(url_for('login'))

    @app.route('/admin_dashboard')
    def admin_dashboard():
        if 'user' not in session or session['user']['role'] != 'SuperUser':
            flash('You need admin privileges to access this page.')
            return redirect(url_for('login'))
        users = app.supabase.table('users').select(
            '*').eq('status', 'pending').execute().data
        return render_template('admin_dashboard.html', users=users)

    @app.route('/approve_user/<int:user_id>')
    def approve_user(user_id):
        if 'user' not in session or session['user']['role'] != 'SuperUser':
            flash('You need admin privileges to access this page.')
            return redirect(url_for('login'))
        user = app.supabase.table('users').select(
            '*').eq('id', user_id).execute().data[0]
        app.supabase.table('users').update(
            {'status': 'approved'}).eq('id', user_id).execute()
        app.supabase.auth.update_user(
            user['auth_user_id'], {'data': {'status': 'approved'}}
        )
        flash('User has been approved.', 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/change_password', methods=['GET', 'POST'])
    def admin_change_password():
        if 'user' not in session or session['user']['role'] != 'SuperUser':
            flash('You need admin privileges to access this page.')
            return redirect(url_for('login'))

        if request.method == 'POST':
            user_id = request.form['user_id']
            new_password = request.form['new_password']

            try:
                response = app.supabase.auth.admin.update_user(
                    user_id, {'password': new_password})

                if response.error:
                    flash(f"Error updating password: {response.error.message}")
                else:
                    flash('Password updated successfully.')
            except Exception as e:
                flash(f"An error occurred: {str(e)}")

        return render_template('admin_change_password.html')

    @app.route('/admin/reset_password/<string:user_email>', methods=['GET', 'POST'])
    def admin_reset_password(user_email):
        if 'user' not in session or session['user']['role'] != 'SuperUser':
            flash('You need admin privileges to access this page.')
            return redirect(url_for('login'))

        form = PasswordResetForm()
        if request.method == 'GET':
            form.user_email.data = user_email

        if form.validate_on_submit():
            new_password = form.new_password.data
            response = app.supabase.auth.api.update_user_by_email(
                user_email, {'password': new_password}
            )
            if response.error:
                flash(f"Error resetting password: {response.error.message}")
            else:
                flash(f"Password reset for {user_email}.", 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_reset_password.html', form=form)

    @app.route('/employment')
    def employment():
        if 'user' not in session:
            flash('You need to be logged in to view this page.')
            return redirect(url_for('login'))

        user_id = session['user']['id']
        employee_data = app.supabase.table('employees').select(
            '*').eq('auth_user_id', user_id).execute().data[0]

        return render_template('employment.html', employee=employee_data)

    @app.route('/myteam_employment')
    def myteam_employment():
        if 'user' not in session:
            flash('You need to be logged in to view this page.')
            return redirect(url_for('login'))

        user_id = session['user']['id']
        user_role = session['user']['role']

        # Adjust roles as per your app's role structure
        if user_role not in ['Manager', 'SuperUser']:
            flash('You do not have the necessary permissions to view this page.')
            return redirect(url_for('dashboard'))

        # Fetch the current user's employee_id
        current_employee = app.supabase.table('employees').select(
            'employee_id').eq('auth_user_id', user_id).execute().data[0]
        current_employee_id = current_employee['employee_id']

        # Fetch employees reporting to the current user
        employees = app.supabase.table('employees').select(
            '*').eq('reports_to', current_employee_id).execute().data
        # Add this line to log the data
        logging.debug(
            f"Employees reporting to {current_employee_id}: {employees}")

        return render_template('myteam_employment.html', employees=employees)

    @app.route('/admin/add_user', methods=['GET', 'POST'])
    def add_user():
        if 'user' not in session or session['user']['role'] != 'SuperUser':
            flash('You need admin privileges to access this page.')
            return redirect(url_for('login'))

        form = RegistrationForm()
        if request.method == 'POST':
            employee_id = request.form['employee_id']
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            role = request.form['role']
            created_at = request.form['created_at']
            updated_at = request.form['updated_at']
            name = request.form['name']
            status = request.form['status']

            # Create user in supabase authentication
            response = app.supabase.auth.sign_up(
                credentials={"email": email, "password": password}
            )

            if 'error' in response:
                flash('Error creating user: ' + response['error']['message'])
                return redirect(url_for('admin_dashboard'))

            # get user id from the authentication response
            auth_id = response['user']['id']

            # Insert user into users table
            result = app.supabase.table('users').insert({
                'email': email,
                'employee_id': employee_id,
                'username': username,
                'password': password,
                'role': role,
                'created_at': created_at,
                'updated_at': updated_at,
                'auth_user_id': auth_id,
                'status': status,
                'Name': name
            }).execute()

            if 'error' in result:
                flash('Error adding user to the database: ' +
                      result['error']['message'])
                return redirect(url_for('admin_dashboard'))

            flash('User created successfully!')
            return redirect(url_for('admin_dashboard'))

        return render_template('add_user.html', form=form)

    @app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
    def edit_user(user_id):
        if 'user' not in session or session['user']['role'] != 'SuperUser':
            flash('You need admin privileges to access this page.')
            return redirect(url_for('login'))

        form = RegistrationForm()
        user = app.supabase.table('employees').select(
            '*').eq('id', user_id).execute().data[0]

        if request.method == 'GET':
            form.name.data = user['employee_name'].strip()
            form.email.data = user['email'].strip()
            form.employee_id.data = user['employee_id'].strip()
            form.title.data = user['title'].strip()
            form.reports_to.data = user['reports_to'].strip() if user['reports_to'] else ''
            form.hire_date.data = user['hire_date']
            form.seniority_date.data = user['seniority_date']
            form.department.data = user['department'].strip()
            form.company_code.data = user['company_code'].strip()
            form.pay_grade.data = user['pay_grade'].strip()

        if form.validate_on_submit():
            app.supabase.table('employees').update({
                'employee_name': form.name.data.strip(),
                'email': form.email.data.strip(),
                'employee_id': form.employee_id.data.strip(),
                'title': form.title.data.strip(),
                'reports_to': form.reports_to.data.strip() if form.reports_to.data else None,
                'hire_date': form.hire_date.data,
                'seniority_date': form.seniority_date.data,
                'department': form.department.data.strip(),
                'company_code': form.company_code.data.strip(),
                'pay_grade': form.pay_grade.data.strip()
            }).eq('id', user_id).execute()
            flash('User updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('edit_user.html', form=form, user_id=user_id)

    @app.route('/electronic_services', methods=['GET', 'POST'])
    def electronic_services():
        if 'user' not in session:
            flash('You need to be logged in to view this page.')
            return redirect(url_for('login'))

        form = UploadForm()
        if form.validate_on_submit():
            file = form.file.data
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_content = file.read()
                file_content_encoded = base64.b64encode(
                    file_content).decode('utf-8')
                file_type = file.filename.rsplit('.', 1)[1].lower()
                user_id = session['user']['id']

                app.supabase.table('electronic_services').insert({
                    'user_id': user_id,
                    'file_name': filename,
                    'file_type': file_type,
                    'file_content': file_content_encoded
                }).execute()

                flash('File uploaded and metadata saved successfully.', 'success')
                return redirect(url_for('electronic_services'))
            else:
                flash(
                    'Invalid file type. Only PDF, DOCX, and CSV are allowed.', 'danger')

        user_id = session['user']['id']
        files = app.supabase.table('electronic_services').select(
            '*').eq('user_id', user_id).execute().data

        return render_template('electronic_services.html', form=form, files=files)

    @app.route('/delete_file/<string:id>', methods=['POST'])
    def delete_file(id):
        if 'user' not in session:
            flash('You need to be logged in to perform this action.')
            return redirect(url_for('login'))

        app.supabase.table('electronic_services').delete().eq(
            'id', id).execute()

        flash('File deleted successfully.', 'success')
        return redirect(url_for('electronic_services'))

    @app.route('/download/<string:id>', methods=['GET'])
    def download_file(id):
        fillable = request.args.get('fillable', False)
        if fillable:
            file_data = app.supabase.table('electronic_services').select(
                'file_name', 'fillable_file_content').eq('id', id).execute().data[0]
            file_content = base64.b64decode(file_data['fillable_file_content'])
            filename = "fillable_" + file_data['file_name']
        else:
            file_data = app.supabase.table('electronic_services').select(
                'file_name', 'file_content').eq('id', id).execute().data[0]
            file_content = base64.b64decode(file_data['file_content'])
            filename = file_data['file_name']

        return send_file(
            io.BytesIO(file_content),
            download_name=filename,
            as_attachment=True
        )

    @app.route('/fill_form/<form_type>', methods=['GET', 'POST'])
    def fill_form(form_type):
        form_classes = {
            'personal_action': PersonalActionForm,
            'leave_request': LeaveRequestForm,
            'personal_leave': PersonalLeaveForm,
            'anonymous_complaint': AnonymousComplaintForm
        }

        form_class = form_classes.get(form_type)
        if not form_class:
            flash('Invalid form type.', 'danger')
            return redirect(url_for('electronic_services'))

        form = form_class()
        if form.validate_on_submit():
            # Handle form submission logic here
            flash('Form submitted successfully.', 'success')
            return redirect(url_for('electronic_services'))

        return render_template(f'{form_type}_form.html', form=form)

    @app.route('/get_employee_details', methods=['GET'])
    def get_employee_details():
        employee_name = request.args.get('employee_name')
        if not employee_name:
            return jsonify({'error': 'Employee name is required'}), 400

        try:
            cleaned_employee_name = employee_name.strip().lower()
            logging.debug(f"Searching for employee with cleaned name: {cleaned_employee_name}")

            response = app.supabase.table('employees').select('*').execute()
            if response.error:
                logging.error(f"Supabase error: {response.error}")
                return jsonify({'error': 'Supabase error', 'message': response.error.message}), 500

            # Filter response data for partial match
            employees = [emp for emp in response.data if cleaned_employee_name in emp['employee_name'].lower()]

            if not employees:
                logging.warning(f"No employee found for cleaned name: {cleaned_employee_name}")
                return jsonify({'error': 'Employee not found'}), 404

            employee = employees[0]
            logging.debug(f"Employee data: {employee}")

            # Fetch supervisor data
            supervisor_response = app.supabase.table('employees').select('title').eq('employee_id', employee['reports_to']).execute()
            logging.debug(f"Supervisor response: {supervisor_response}")

            if supervisor_response.error:
                logging.error(f"Supabase error (supervisor): {supervisor_response.error}")
                return jsonify({'error': 'Supabase error (supervisor)', 'message': supervisor_response.error.message}), 500

            supervisor_position = supervisor_response.data[0]['title'] if supervisor_response.data else ''

            result = {
                'position_title': employee.get('title', '').strip(),
                'position_id': employee.get('position_id', '').strip(),
                'department': employee.get('department', '').strip(),
                'company_code': employee.get('company_code', '').strip(),
                'pay_grade': employee.get('pay_grade', '').strip(),
                'supervisor_position': supervisor_position.strip() if supervisor_position else ''
            }

            logging.debug(f"Resulting JSON: {json.dumps(result)}")
            return jsonify(result)

        except Exception as e:
            logging.error(f"Error fetching employee details: {e}")
            logging.error(traceback.format_exc())
            return jsonify({'error': 'Internal server error', 'message': str(e)}), 500
