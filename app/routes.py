from app import app


@app.route('/')
def index():
    return "Welcome to the HR Suite!"


@app.route('/dashboard')
def dashboard():
    return "This is the dashboard page."
