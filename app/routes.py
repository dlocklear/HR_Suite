from flask import Flask, render_template, request, redirect, session, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
import os
from supabase import create_client, Client
from app.forms import RegistrationForm, PasswordResetForm, UploadForm
from app import bcrypt
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import uuid
from pdfrw import PdfReader, PdfWriter, PageMerge

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

            # Call Supabase to authenticate the user
            response = app.supabase.auth.sign_in_with_password(
                {"email": email, "password": password})

            if response.user:
                user_data = app.supabase.table('users').select(
                    'role').eq('auth_user_id', response.user.id).execute()
                # Store user details in session to keep them logged in
                session['user'] = {
                    'id': response.user.id,
                    'email': response.user.email,
                    'role': user_data.data[0]['role']  # Store role in session
                }
                return redirect(url_for('dashboard'))
            else:
                # If no user is returned, handle errors
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
                # Insert the new user into the users table
                app.supabase.table('users').insert({
                    'name': form.name.data,
                    'email': form.email.data,
                    'password': hashed_password,
                    'status': 'pending',
                    'auth_user_id': response.user.id
                }).execute()

                # Insert the new user into the employees table
                app.supabase.table('employees').insert({
                    'name': form.name.data,
                    'email': form.email.data,
                    'auth_user_id': response.user.id,
                    'employee_id': form.employee_id.data,
                    'title': form.title.data,
                    'reports_to': form.reports_to.data,
                    'position_id': form.position_id.data,
                    'hire_date': form.hire_date.data,
                    'seniority_date': form.seniority_date.data,
                    'department': form.department.data
                }).execute()

                # Send confirmation email using SendGrid
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
        # Remove user from session
        session.pop('user', None)
        # Redirect to login page with a success message
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
        # Update Supabase authentication
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
                # Update user's password using Supabase Admin API
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
        
        # Fetch the user's information from the employees table
        user_id = session['user']['id']
        employee_data = app.supabase.table('employees').select('*').eq('auth_user_id', user_id).execute().data[0]
        
        return render_template('employment.html', employee=employee_data)

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
                'position_id': form.position_id.data,
                'hire_date': form.hire_date.data,
                'seniority_date': form.seniority_date.data,
                'department': form.department.data,
                'auth_user_id': generate_employee_id(),  # Assuming a function to generate auth_user_id
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
            form.position_id.data = user['position_id']
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
                'position_id': form.position_id.data,
                'hire_date': form.hire_date.data,
                'seniority_date': form.seniority_date.data,
                'department': form.department.data
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
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                file_url = url_for('uploaded_file', filename=filename, _external=True)
                
                app.supabase.table('electronic_services').insert({
                    'user_id': session['user']['id'],
                    'file_name': filename,
                    'file_type': file.filename.rsplit('.', 1)[1].lower(),
                    'file_url': file_url
                }).execute()
                
                flash('File uploaded and metadata saved successfully.', 'success')
                return redirect(url_for('electronic_services'))
            else:
                flash('Invalid file type. Only PDF, DOCX, and CSV are allowed.', 'danger')

        # Fetch the list of uploaded files
        user_id = session['user']['id']
        files = app.supabase.table('electronic_services').select('*').eq('user_id', user_id).execute().data

        return render_template('electronic_services.html', form=form, files=files)

    @app.route('/convert_to_fillable/<file_id>', methods=['GET'])
    def convert_to_fillable(file_id):
        # Fetch the file metadata from the electronic_services table
        file_data = app.supabase.table('electronic_services').select('*').eq('id', file_id).execute().data[0]
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data['file_name'])

        # Perform the conversion to fillable PDF
        fillable_file_name = 'fillable_' + file_data['file_name']
        fillable_file_path = os.path.join(app.config['UPLOAD_FOLDER'], fillable_file_name)
        convert_to_fillable_pdf(file_path, fillable_file_path)

        # Debug: print the file paths
        print(f"Original file path: {file_path}")
        print(f"Fillable file path: {fillable_file_path}")

        # Update the database with the new fillable file URL
        fillable_file_url = url_for('uploaded_file', filename=fillable_file_name, _external=True)
        app.supabase.table('electronic_services').update({'fillable_file_url': fillable_file_url}).eq('id', file_id).execute()

        flash('File converted to fillable PDF successfully.', 'success')
        return redirect(url_for('electronic_services'))

    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        # Debug: print the filename being requested
        print(f"Requested filename: {filename}")
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def generate_employee_id():
    # Implement your logic to generate a unique employee ID
    return 'EMP' + str(uuid.uuid4())

def convert_to_fillable_pdf(input_path, output_path):
    template_pdf = PdfReader(input_path)
    output_pdf = PdfWriter()

    for page in template_pdf.pages:
        page_merge = PageMerge(page)
        page_merge.render()
        output_pdf.addpage(page)

    output_pdf.write(output_path)
