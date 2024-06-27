import logging
from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file
from werkzeug.utils import secure_filename
import os
import base64
from supabase import create_client, Client
from app.forms import RegistrationForm, PasswordResetForm, UploadForm
from app import bcrypt
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import uuid
import io
from pdfrw import PdfReader, PdfWriter, PageMerge  # Correct import

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
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
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
                    'name': form.name.data,
                    'email': form.email.data,
                    'auth_user_id': response.user.id,
                    'employee_id': form.employee_id.data,
                    'title': form.title.data,
                    'reports_to': form.reports_to.data,
                    'hire_date': form.hire_date.data,
                    'seniority_date': form.seniority_date.data,
                    'department': form.department.data
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

                flash('Your account has been created! Wait for admin approval.', 'success')
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
        users = app.supabase.table('users').select('*').eq('status', 'pending').execute().data
        return render_template('admin_dashboard.html', users=users)

    @app.route('/approve_user/<int:user_id>')
    def approve_user(user_id):
        if 'user' not in session or session['user']['role'] != 'SuperUser':
            flash('You need admin privileges to access this page.')
            return redirect(url_for('login'))
        user = app.supabase.table('users').select('*').eq('id', user_id).execute().data[0]
        app.supabase.table('users').update({'status': 'approved'}).eq('id', user_id).execute()
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
        employee_data = app.supabase.table('employees').select('*').eq('auth_user_id', user_id).execute().data[0]
        
        return render_template('employment.html', employee=employee_data)

    @app.route('/myteam_employment')
    def myteam_employment():
        if 'user' not in session:
            flash('You need to be logged in to view this page.')
            return redirect(url_for('login'))

        user_id = session['user']['id']
        user_role = session['user']['role']
        
        if user_role not in ['Manager', 'SuperUser']:  # Adjust roles as per your app's role structure
            flash('You do not have the necessary permissions to view this page.')
            return redirect(url_for('dashboard'))

        # Fetch the current user's employee_id
        current_employee = app.supabase.table('employees').select('employee_id').eq('auth_user_id', user_id).execute().data[0]
        current_employee_id = current_employee['employee_id']
        
        # Fetch employees reporting to the current user
        employees = app.supabase.table('employees').select('*').eq('reports_to', current_employee_id).execute().data
        logging.debug(f"Employees reporting to {current_employee_id}: {employees}")  # Add this line to log the data

        return render_template('myteam_employment.html', employees=employees)

    @app.route('/manager/employment', methods=['GET'])
    def manager_employees():
        if 'user' not in session or session['user']['role'] != 'manager':
            flash('You need to be a manager to access this page.')

        # Assuming user_id is stored in session
        auth_user_id = session['user']['id']
        print(f"User ID: {auth_user_id}")  # Debugging line to check user_id

        # Fetch employee_id using user_id
        manager_response = app.supabase.table('users').select(
            'employee_id').eq('auth_user_id', auth_user_id).execute()

        manager_id = manager_response.data[0]['employee_id']
        print(f"Manager id: {manager_id}")

        # Fetch employees who report to this manager
        response = app.supabase.from_('employees').select(
            '*').eq('reports_to', manager_id).execute()

        employees = response.data
        print(f"Employees: {employees}")
        return render_template('manager_employees.html', employees=employees)

    @app.route('/admin/add_user', methods=['GET', 'POST'])
    def add_user():
        if 'user' not in session or session['user']['role'] != 'SuperUser':
            flash('You need admin privileges to access this page.')
            return redirect(url_for('login'))

        form = RegistrationForm()
        if form.validate_on_submit():
            app.supabase.table('employees').insert({
                'name': form.name.data,
                'email': form.email.data,
                'employee_id': form.employee_id.data,
                'title': form.title.data,
                'reports_to': form.reports_to.data,
                'hire_date': form.hire_date.data,
                'seniority_date': form.seniority_date.data,
                'department': form.department.data,
                'auth_user_id': form.auth_user_id.data
            }).execute()
            flash('User added successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('add_user.html', form=form)

    @app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
    def edit_user(user_id):
        if 'user' not in session or session['user']['role'] != 'SuperUser':
            flash('You need admin privileges to access this page.')
            return redirect(url_for('login'))

        form = RegistrationForm()
        user = app.supabase.table('employees').select('*').eq('id', user_id).execute().data[0]

        if request.method == 'GET':
            form.name.data = user['name']
            form.email.data = user['email']
            form.employee_id.data = user['employee_id']
            form.title.data = user['title']
            form.reports_to.data = user['reports_to']
            form.hire_date.data = user['hire_date']
            form.seniority_date.data = user['seniority_date']
            form.department.data = user['department']

        if form.validate_on_submit():
            app.supabase.table('employees').update({
                'name': form.name.data,
                'email': form.email.data,
                'employee_id': form.employee_id.data,
                'title': form.title.data,
                'reports_to': form.reports_to.data,
                'hire_date': form.hire_date.data,
                'seniority_date': form.seniority_date.data,
                'department': form.department.data,
                'auth_user_id': form.auth_user_id.data
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
                file_content_encoded = base64.b64encode(file_content).decode('utf-8')
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
                flash('Invalid file type. Only PDF, DOCX, and CSV are allowed.', 'danger')

        user_id = session['user']['id']
        files = app.supabase.table('electronic_services').select('*').eq('user_id', user_id).execute().data

        return render_template('electronic_services.html', form=form, files=files)

    @app.route('/convert_to_fillable/<string:id>', methods=['GET'])
    def convert_to_fillable(id):
        file_data = app.supabase.table('electronic_services').select('*').eq('id', id).execute().data[0]
        file_content = base64.b64decode(file_data['file_content'])
        
        # Assuming convert_to_fillable_pdf function is updated to handle file content directly
        fillable_file_content = convert_to_fillable_pdf(file_content)
        fillable_file_content_encoded = base64.b64encode(fillable_file_content).decode('utf-8')

        app.supabase.table('electronic_services').update({
            'fillable_file_content': fillable_file_content_encoded
        }).eq('id', id).execute()

        flash('File converted to fillable PDF successfully.', 'success')
        return redirect(url_for('electronic_services'))

    @app.route('/delete_file/<string:id>', methods=['POST'])
    def delete_file(id):
        if 'user' not in session:
            flash('You need to be logged in to perform this action.')
            return redirect(url_for('login'))

        app.supabase.table('electronic_services').delete().eq('id', id).execute()

        flash('File deleted successfully.', 'success')
        return redirect(url_for('electronic_services'))

    @app.route('/download/<string:id>', methods=['GET'])
    def download_file(id):
        fillable = request.args.get('fillable', False)
        if fillable:
            file_data = app.supabase.table('electronic_services').select('file_name', 'fillable_file_content').eq('id', id).execute().data[0]
            file_content = base64.b64decode(file_data['fillable_file_content'])
            filename = "fillable_" + file_data['file_name']
        else:
            file_data = app.supabase.table('electronic_services').select('file_name', 'file_content').eq('id', id).execute().data[0]
            file_content = base64.b64decode(file_data['file_content'])
            filename = file_data['file_name']

        return send_file(
            io.BytesIO(file_content),
            download_name=filename,
            as_attachment=True
        )

def generate_employee_id():
    return 'EMP' + str(uuid.uuid4())

def convert_to_fillable_pdf(file_content):
    template_pdf = PdfReader(io.BytesIO(file_content))
    output_pdf = PdfWriter()

    for page in template_pdf.pages:
        page_merge = PageMerge(page)
        page_merge.render()
        output_pdf.addpage(page)

    output_stream = io.BytesIO()
    output_pdf.write(output_stream)
    output_stream.seek(0)

    return output_stream.read()
