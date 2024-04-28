from flask import render_template


def init_routes(app):
    @app.route('/')
    def index():
        return "Welcome to the HR Suite!"

    @app.route('/dashboard')
    def dashboard():
        return "This is the dashboard page."

    @app.route('/login')
    def login():
        return render_template('login.html')
