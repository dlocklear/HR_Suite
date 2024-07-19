import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file, Blueprint
from supabase import create_client
from app.forms import RegistrationForm, PasswordResetForm, UploadForm, PersonalActionForm, LeaveRequestForm, PersonalLeaveForm, AnonymousComplaintForm
from app import bcrypt
from werkzeug.utils import secure_filename
import os
import base64
import uuid
import io

logging.basicConfig(level=logging.DEBUG)

bp = Blueprint('routes', __name__)


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
                    'Department': form.department.data,
                    'Company_Code': form.company_code.data,
                    'pay_grade': form.pay_grade.data
                }).execute()

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
        form = RegistrationForm()
        if form.validate_on_submit():
            # Extract data
            name = form.name.data
            user_id = form.user_id.data
            username = form.username.data
            email = form.email.data
            password = form.password.data
            role = form.role.data
            employee_id = form.employee_id.data
            title = form.title.data
            reports_to = form.reports_to.data
            position_id = form.position_id.data
            hire_date = form.hire_date.data
            created_at = form.created_at.data
            updated_at = form.updated_at.data
            seniority_date = form.seniority_date.data
            department = form.department.data
            status = form.status.data

            # Generate unique token for email confirmation
            confirmation_token = str(uuid.uuid4())

            # Hash password
            hashed_password = bcrypt.generate_password_hash(
                password).decode('utf-8')

            # Prepare user data for supabase
            user_data = {
                "name": name,
                "user_id": user_id,
                "username": username,
                "email": email,
                "password": hashed_password,
                "role": role,
                "employee_id": employee_id,
                "title": title,
                "reports_to": reports_to,
                "position_id": position_id,
                "hire_date": hire_date,
                "created_at": created_at,
                "updated_at": updated_at,
                "seniority_date": seniority_date,
                "department": department,
                "status": status
            }

            """
            Store user data in a temporary table or cache (this part is simplified, you might need a proper temporary storage)
            This example uses an in-memory dictionary, consider using a persistent store for production
            """
            app.config['PENDING_USERS'] = app.config.get(
                'PENDING_USERS', {})
            app.config['PENDING_USERS'][confirmation_token] = user_data

            # Send confirmation email
            confirmation_url = url_for(
                'confirm_user', token=confirmation_token, _external=True)
            email_body = f"Please click the following link to confirm your registration: {confirmation_url}"
            app.send_email(email, "Confirm your registration", email_body)

            flash("A confirmation email has been sent. Please check your inbox.", "info")
            return redirect(url_for('routes.add_user'))

        return render_template('add_user.html', form=form)

    @bp.route('/confirm_user/<token>', methods=['GET'])
    def confirm_user(token):
        pending_users = app.config.get('PENDING_USERS', {})
        user_data = pending_users.pop(token, None)

        if not user_data:
            flash("Invalid or expired confirmation link.", "danger")
            return redirect(url_for('routes.add_user'))

        # Insert user data into Supabase authentication and users tables
        try:
            supabase = app.supabase

            # Add user to the authentication table
            auth_response = supabase.auth.sign_up({
                'email': user_data['email'],
                'password': user_data['password']
            })

            if 'error' in auth_response:
                raise Exception(auth_response['error']['message'])

            # Add user to the users table
            response = supabase.table("users").insert(user_data).execute()
            if response.status_code != 201:
                raise Exception("Failed to add user to the users table.")

            flash("User successfully confirmed and added.", "success")
            return redirect(url_for('add_user.html'))
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('add_user.html'))

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
            form.reports_to.data = user['reports_to'].strip(
            ) if user['reports_to'] else ''
            form.hire_date.data = user['hire_date']
            form.seniority_date.data = user['seniority_date']
            form.department.data = user['Department'].strip()
            form.company_code.data = user['Company_Code'].strip()
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
                'Department': form.department.data.strip(),
                'Company_Code': form.company_code.data.strip(),
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
            # Clean the employee name by stripping whitespaces and newline characters
            cleaned_employee_name = employee_name.strip()
            query = f"%{cleaned_employee_name}%"
            logging.debug(f"Searching for employee with query: {query}")

            response = app.supabase.table('employees').select(
                '*').ilike('employee_name', query).execute()
            logging.debug(f"Supabase response: {response}")

            if not response.data:
                return jsonify({'error': 'Employee not found'}), 404

            employee_data = response.data
            logging.debug(f"Employee data response: {employee_data}")

            employee = employee_data[0]
            supervisor_data = app.supabase.table('employees').select(
                '*').eq('employee_id', employee['reports_to']).execute().data
            supervisor_position = supervisor_data[0]['title'] if supervisor_data else ''

            result = {
                'position_title': employee['title'].strip(),
                'position_id': employee['position_id'].strip(),
                'department': employee['Department'].strip(),
                'company_code': employee['Company_Code'].strip(),
                'pay_grade': employee['pay_grade'].strip(),
                'supervisor_position': supervisor_position
            }

            logging.debug(f"Resulting JSON: {result}")
            return jsonify(result)
        except Exception as e:
            logging.error(
                f"Error fetching employee details: {e}", exc_info=True)
            return jsonify({'error': 'Internal server error', 'message': str(e)}), 500
