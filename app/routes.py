from flask import Flask, render_template, request, redirect, session, url_for, flash
from supabase import create_client, Client

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
                error_message = response.error.message if response.error else "login failed."
                flash(error_message)

        return render_template('login.html')

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

    @app.route('/admin/change_password', methods=['GET', 'POST'])
    def admin_change_password():
        if 'user' not in session or session['user']['role'] != 'admin':
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
