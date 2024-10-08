from decimal import Decimal
import logging
import datetime
import traceback
import base64
import uuid
from werkzeug.utils import secure_filename
from flask import render_template, request, jsonify, session, redirect, url_for, flash, send_file
import io
from app.forms import PerformanceEvaluationForm, RegistrationForm, PasswordResetForm, UploadForm, PersonalActionForm, LeaveRequestForm, PersonalLeaveForm, AnonymousComplaintForm, CreateUserForm, NotificationForm
from app import send_email, bcrypt
from app.utils.notifications import send_notification, send_notifications_to_all, send_notifications_to_role, send_notification_to_employee

logging.basicConfig(level=logging.DEBUG)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"pdf", "docx", "csv"}


def init_routes(app):
    @app.route("/")
    def index():
        if "user" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form["email"]
            password = request.form["password"]
            response = app.supabase.auth.sign_in_with_password(
                {"email": email, "password": password})
            if response.user:
                user_data = app.supabase.table("users").select(
                    "role").eq("auth_user_id", response.user.id).execute()
                session["user"] = {
                    "id": response.user.id,
                    "email": response.user.email,
                    "role": user_data.data[0]["role"],
                }
                return redirect(url_for("dashboard"))
            else:
                error_message = response.error.message if response.error else "Login failed."
                flash(error_message)
        return render_template("login.html")

    @app.route("/dashboard")
    def dashboard():
        if "user" not in session:
            flash("You need to be logged in to view the dashboard.")
            return redirect(url_for("login"))
        return render_template("dashboard.html")

    @app.route("/logout")
    def logout():
        session.pop("user", None)
        flash("You have successfully logged out.")
        return redirect(url_for("login"))

    @app.route("/admin_dashboard")
    def admin_dashboard():
        if "user" not in session or session["user"]["role"] != "SuperUser":
            flash("You need admin privileges to access this page.")
            return redirect(url_for("login"))
        users = app.supabase.table("users").select("*").eq("status", "pending").execute().data
        return render_template("admin_dashboard.html", users=users)


    @app.route("/approve_user/<string:auth_user_id>")
    def approve_user(auth_user_id):
        if "user" not in session or session["user"]["role"] != "SuperUser":
            flash("You need admin privileges to access this page.")
            return redirect(url_for("login"))
    
        user = app.supabase.table("users").select("*").eq("auth_user_id", auth_user_id).execute().data[0]
        app.supabase.table("users").update({"status": "approved"}).eq("auth_user_id", auth_user_id).execute()
        app.supabase.auth.update_user(user["auth_user_id"], {"data": {"status": "approved"}})
    
        flash("User has been approved.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user_data = {
                "email": form.email.data,
                "password": password_hash,
                "role": form.role.data,
            }
            response = app.supabase.auth.sign_up(user_data)
            if response.user:
                app.supabase.table("users").insert({
                    "auth_user_id": response.user.id,
                    "email": form.email.data,
                    "role": form.role.data,
                    "status": "pending"
                }).execute()
                flash("Registration successful. Please wait for admin approval.", "success")
                return redirect(url_for("login"))
            else:
                flash("An error occurred during registration.", "danger")
        return render_template("register.html", form=form)

    @app.route("/admin/change_password", methods=["GET", "POST"])
    def admin_change_password():
        if "user" not in session or session["user"]["role"] != "SuperUser":
            flash("You need admin privileges to access this page.")
            return redirect(url_for("login"))

        if request.method == "POST":
            user_id = request.form["user_id"]
            new_password = request.form["new_password"]

            try:
                response = app.supabase.auth.admin.update_user(
                    user_id, {"password": new_password})
                if response.error:
                    flash(f"Error updating password: {response.error.message}")
                else:
                    flash("Password updated successfully.")
            except Exception as e:
                flash(f"An error occurred: {str(e)}")

        return render_template("admin_change_password.html")

    @app.route("/admin/reset_password/<string:user_email>", methods=["GET", "POST"])
    def admin_reset_password(user_email):
        if "user" not in session or session["user"]["role"] != "SuperUser":
            flash("You need admin privileges to access this page.")
            return redirect(url_for("login"))

        form = PasswordResetForm()
        if request.method == "GET":
            form.user_email.data = user_email

        if form.validate_on_submit():
            new_password = form.new_password.data
            response = app.supabase.auth.api.update_user_by_email(
                user_email, {"password": new_password}
           )
            if response.error:
                flash(f"Error resetting password: {response.error.message}")
            else:
                flash(f"Password reset for {user_email}.", "success")
            return redirect(url_for("admin_dashboard"))
        return render_template("admin_reset_password.html", form=form)

    @app.route("/employment")
    def employment():
        if "user" not in session:
            flash("You need to be logged in to view this page.")
            return redirect(url_for("login"))

        user_id = session["user"]["id"]
        employee_data = app.supabase.table("employees").select(
            "*").eq("auth_user_id", user_id).execute().data[0]

        return render_template("employment.html", employee=employee_data)

    @app.route("/myteam_employment")
    def myteam_employment():
        if "user" not in session:
            flash("You need to be logged in to view this page.")
            return redirect(url_for("login"))

        user_id = session["user"]["id"]
        user_role = session["user"]["role"]

        if user_role not in ["Manager", "SuperUser"]:
            flash("You do not have the necessary permissions to view this page.")
            return redirect(url_for("dashboard"))

        current_employee = app.supabase.table("employees").select(
            "employee_id").eq("auth_user_id", user_id).execute().data[0]
        current_employee_id = current_employee["employee_id"]

        employees = app.supabase.table("employees").select(
            "*").eq("reports_to", current_employee_id).execute().data

        logging.debug(
            f"Employees reporting to {current_employee_id}: {employees}")

        return render_template("myteam_employment.html", employees=employees)

    @app.route("/admin/edit_user/<string:auth_user_id>", methods=["GET", "POST"])
    def edit_user(auth_user_id):
        if "user" not in session or session["user"]["role"] != "SuperUser":
            flash("You need admin privileges to access this page.")
            return redirect(url_for("login"))

        form = RegistrationForm()
        user = app.supabase.table("users").select("*").eq("auth_user_id", auth_user_id).execute().data[0]

        if request.method == "GET":
            form.name.data = user["employee_name"].strip()
            form.email.data = user["email"].strip()
            form.employee_id.data = user["employee_id"].strip()
            form.title.data = user["title"].strip()
            form.reports_to.data = user["reports_to"].strip() if user["reports_to"] else ""
            form.hire_date.data = user["hire_date"]
            form.seniority_date.data = user["seniority_date"]
            form.department.data = user["department"].strip()
            form.company_code.data = user["company_code"].strip()
            form.pay_grade.data = user["pay_grade"].strip()

        if form.validate_on_submit():
            app.supabase.table("users").update({
                "employee_name": form.name.data.strip(),
                "email": form.email.data.strip(),
                "employee_id": form.employee_id.data.strip(),
                "title": form.title.data.strip(),
                "reports_to": form.reports_to.data.strip() if form.reports_to.data else None,
                "hire_date": form.hire_date.data,
                "seniority_date": form.seniority_date.data,
                "department": form.department.data.strip(),
                "company_code": form.company_code.data.strip(),
                "pay_grade": form.pay_grade.data.strip(),
            }).eq("auth_user_id", auth_user_id).execute()
            flash("User updated successfully.", "success")
            return redirect(url_for("admin_dashboard"))
        return render_template("edit_user.html", form=form, user_id=auth_user_id)


    @app.route("/electronic_services", methods=["GET", "POST"])
    def electronic_services():
        if "user" not in session:
            flash("You need to be logged in to view this page.")
            return redirect(url_for("login"))

        form = UploadForm()
        if form.validate_on_submit():
            file = form.file.data
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_content = file.read()
                file_content_encoded = base64.b64encode(
                    file_content).decode("utf-8")
                file_type = file.filename.rsplit(".", 1)[1].lower()
                user_id = session["user"]["id"]

                app.supabase.table("electronic_services").insert({
                    "user_id": user_id,
                    "file_name": filename,
                    "file_type": file_type,
                    "file_content": file_content_encoded,
                }).execute()

                flash("File uploaded and metadata saved successfully.", "success")
                return redirect(url_for("electronic_services"))
            else:
                flash(
                    "Invalid file type. Only PDF, DOCX, and CSV are allowed.", "danger")

        user_id = session["user"]["id"]
        files = app.supabase.table("electronic_services").select(
            "*").eq("user_id", user_id).execute().data

        return render_template("electronic_services.html", form=form, files=files)

    @app.route("/delete_file/<string:id>", methods=["POST"])
    def delete_file(id):
        if "user" not in session:
            flash("You need to be logged in to perform this action.")
            return redirect(url_for("login"))

        app.supabase.table("electronic_services").delete().eq(
            "id", id).execute()

        flash("File deleted successfully.", "success")
        return redirect(url_for("electronic_services"))

    @app.route("/download/<string:id>", methods=["GET"])
    def download_file(id):
        fillable = request.args.get("fillable", False)
        if fillable:
            file_data = app.supabase.table("electronic_services").select(
                "file_name", "fillable_file_content").eq("id", id).execute().data[0]
            file_content = base64.b64decode(file_data["fillable_file_content"])
            filename = "fillable_" + file_data["file_name"]
        else:
            file_data = app.supabase.table("electronic_services").select(
                "file_name", "file_content").eq("id", id).execute().data[0]
            file_content = base64.b64decode(file_data["file_content"])
            filename = file_data["file_name"]

        return send_file(io.BytesIO(file_content), download_name=filename, as_attachment=True)

    @app.route("/fill_form/<form_type>", methods=["GET", "POST"])
    def fill_form(form_type):
        form_classes = {
            "personal_action": PersonalActionForm,
            "leave_request": LeaveRequestForm,
            "personal_leave": PersonalLeaveForm,
            "anonymous_complaint": AnonymousComplaintForm,
        }

        form_class = form_classes.get(form_type)
        if not form_class:
            flash("Invalid form type.", "danger")
            return redirect(url_for("electronic_services"))

        form = form_class()
        if form.validate_on_submit():
            flash("Form submitted successfully.", "success")
            return redirect(url_for("electronic_services"))

        return render_template(f"{form_type}_form.html", form=form)

    @app.route('/get_employee_details', methods=['GET'])
    def get_employee_details():
        employee_name = request.args.get('employee_name')
        if not employee_name:
            return jsonify({'error': 'Employee name is required'}), 400

        try:
            cleaned_employee_name = employee_name.strip().lower()
            logging.debug(
                "Searching for employee with cleaned name: %s", cleaned_employee_name)

            response = app.supabase.table('employees').select('*').execute()
            if response.error:
                logging.error(f"Supabase error: {response.error}")
                return jsonify({'error': 'Supabase error', 'message': response.error.message}), 500

            employees = [
                emp for emp in response.data if cleaned_employee_name in emp['employee_name'].lower()]

            if not employees:
                logging.warning(
                    f"No employee found for cleaned name: {cleaned_employee_name}")
                return jsonify({'error': 'Employee not found'}), 404

            employee = employees[0]
            logging.debug(f"Employee data: {employee}")

            supervisor_response = app.supabase.table('employees').select(
                'title').eq('employee_id', employee['reports_to']).execute()
            logging.debug(f"Supervisor response: {supervisor_response}")

            if supervisor_response.error:
                logging.error(
                    f"Supabase error (supervisor): {supervisor_response.error}")
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
            logging.error("Error fetching employee details: %s", e)
            logging.error(traceback.format_exc())
            return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

    @app.route('/myteam/complete_evaluations', methods=['GET', 'POST'])
    def complete_evaluations():
        form = PerformanceEvaluationForm()

        # Fetch employees for the dropdown
        try:
            user_id = session['user']['id']
            current_employee = app.supabase.table('employees').select(
                'employee_id').eq('auth_user_id', user_id).execute().data[0]
            current_employee_id = current_employee['employee_id']
            employees = app.supabase.table('employees').select(
                'employee_name, employee_id').eq('reports_to', current_employee_id).execute().data
            form.employee_id.choices = [
                (employee['employee_id'], employee['employee_name']) for employee in employees]
            logging.debug("Employees fetched for dropdown: %s",
                          form.employee_id.choices)
        except Exception as e:
            logging.error("Error fetching employees: %s", e)
            flash("Error fetching employees.", "danger")
            form.employee_id.choices = []

        if form.validate_on_submit():
            logging.debug("Form validated successfully.")
            try:
                employee_id = form.employee_id.data
                business_result = form.business_result.data
                individual_result = form.individual_result.data
                safety_result = form.safety_result.data
                logging.debug(
                    f"Form data: employee_id={employee_id}, business_result={business_result}, individual_result={individual_result}, safety_result={safety_result}")

                # Correct query now that employee_id is in position table
                position_response = app.supabase.table('position').select(
                    'pay_grade').eq('employee_id', employee_id).execute()
                if not position_response.data:
                    flash('Position data not found', 'danger')
                    return redirect(url_for('complete_evaluations'))
                pay_grade = position_response.data[0]['pay_grade']
                salary_response = app.supabase.table('salaries').select(
                    'current_salary').eq('employee_id', employee_id).execute()
                if not salary_response.data:
                    flash('Salary data not found', 'danger')
                    return redirect(url_for('complete_evaluations'))
                salary = Decimal(salary_response.data[0]['current_salary'])
                pay_band_response = app.supabase.table('pay_bands').select(
                    '*').eq('band', pay_grade).execute()
                if not pay_band_response.data:
                    flash('Pay band data not found', 'danger')
                    return redirect(url_for('complete_evaluations'))

                pay_band = pay_band_response.data[0]

                # Convert values to Decimal
                target_award = Decimal(pay_band['target_award'])
                business_weight = Decimal(pay_band['business_weight'])
                individual_weight = Decimal(pay_band['individual_weight'])
                safety_weight = Decimal(pay_band['safety_weight'])

                # Convert results to Decimal and calculate
                business_result = Decimal(business_result) / Decimal(100)
                individual_result = Decimal(individual_result) / Decimal(100)
                safety_result = Decimal(safety_result) / Decimal(100)

                # Calculate target bonus
                target_bonus = salary * target_award
                business_contribution = target_bonus * business_weight
                individual_contribution = target_bonus * individual_weight
                safety_contribution = target_bonus * safety_weight

                # Calculate actual bonus payout
                actual_business = business_contribution * business_result
                actual_individual = individual_contribution * individual_result
                actual_safety = safety_contribution * safety_result

                bonus_payout = actual_business + actual_individual + actual_safety

                # Prepare data for insertion
                data = {
                    'employee_id': employee_id,
                    'business_result': float(business_result),
                    'individual_result': float(individual_result),
                    'safety_result': float(safety_result),
                    'bonus_payout': float(bonus_payout),
                    'evaluation_date': datetime.date.today().isoformat(),  # Convert date to string
                    'submitted_at': datetime.datetime.now().isoformat(),    # Convert datetime to string
                    'submitted_by': user_id
                }
                logging.debug(f"Data prepared for insertion: {data}")

                insert_response = app.supabase.table(
                    'performance_reviews').insert(data).execute()
                logging.debug(f"Insert response: {insert_response}")

                if insert_response.data:
                    flash("Evaluation submitted successfully.", "success")
                else:
                    flash(
                        "An error occurred while submitting the evaluation.", "danger")

                return redirect(url_for('complete_evaluations'))

            except Exception as e:
                logging.error(f"Error processing form: {e}")
                logging.error(traceback.format_exc())
                flash("An error occurred while submitting the evaluation.", "danger")
        else:
            logging.debug("Form did not validate.")

        return render_template('complete_evaluations.html', form=form)

    @app.route("/myteam/performance_dashboard")
    def performance_dashboard():
        return render_template("myteam_performance_dashboard.html")

    @app.route("/myteam/view_evaluations", methods=["GET", "POST"])
    def view_evaluations():
        if "user" not in session:
            flash("You need to be logged in to view this page.")
            return redirect(url_for("login"))

        user_id = session["user"]["id"]
        logging.debug(f"User ID: {user_id}")

        try:
            # Fetch the current manager's employee_id
            manager_response = app.supabase.table("employees").select(
                "employee_id").eq("auth_user_id", user_id).execute()
            logging.debug(f"Manager response: {manager_response}")

            if not manager_response.data:
                logging.warning(
                    f"Manager data not found for user ID: {user_id}")
                flash("Manager data not found.", "danger")
                return redirect(url_for("dashboard"))

            manager_employee_id = manager_response.data[0]["employee_id"]
            logging.debug(f"Manager Employee ID: {manager_employee_id}")

            # Fetch employees reporting to the current manager
            employees_response = app.supabase.table("employees").select(
                "employee_name, employee_id").eq("reports_to", manager_employee_id).execute()
            logging.debug(f"Employees response: {employees_response}")

            if not employees_response.data:
                logging.warning(
                    f"No employees found reporting to manager with ID: {manager_employee_id}")
                flash("No employees found reporting to you.", "warning")
                return redirect(url_for("dashboard"))

            employees = employees_response.data

            if request.method == "POST":
                selected_employee_id = request.form.get("employee_id")
                logging.debug(f"Selected Employee ID: {selected_employee_id}")

                if selected_employee_id:
                    reviews_response = app.supabase.table("performance_reviews").select(
                        "*").eq("employee_id", selected_employee_id).execute()
                    logging.debug(f"Reviews Response: {reviews_response}")

                    if reviews_response.data:
                        reviews = reviews_response.data
                        return render_template("myteam_view_evaluations.html", employees=employees, reviews=reviews)
                    else:
                        logging.warning(
                            f"No reviews found for employee with ID: {selected_employee_id}")
                        flash(
                            "No reviews found for the selected employee.", "warning")
                        return redirect(url_for("view_evaluations"))

            return render_template("myteam_view_evaluations.html", employees=employees)

        except Exception as e:
            logging.error(f"Error fetching evaluations: {e}")
            logging.error(traceback.format_exc())
            flash("An error occurred while fetching evaluations.", "danger")
            return redirect(url_for("dashboard"))

    @app.route("/people/performance_dashboard")
    def people_performance_dashboard():
        return render_template("people_performance_dashboard.html")

    @app.route("/people/view_performance_reviews", methods=["GET"])
    def people_view_performance_reviews():
        if "user" not in session:
            flash("You need to be logged in to view this page.")
            return redirect(url_for("login"))

        reviews = app.supabase.table(
            "performance_reviews").select("*").execute().data
        return render_template("people_view_performance_reviews.html", reviews=reviews)

    @app.route("/people/redirect_evaluation", methods=["GET", "POST"])
    def people_redirect_evaluation():
        if request.method == "POST":
            pass

        employees = app.supabase.table("employees").select(
            "employee_id", "employee_name", "auth_user_id").execute().data

        managers = []
        for employee in employees:
            user_data = app.supabase.table("users").select("role").eq(
                "user_id", employee["auth_user_id"]).execute().data
            if user_data and user_data[0]["role"] == "Manager":
                managers.append(
                    {"employee_id": employee["employee_id"], "employee_name": employee["employee_name"]})

        evaluations = []
        return render_template("people_redirect_evaluation.html", evaluations=evaluations, managers=managers)

    @app.route("/myteam/performance_reports")
    def performance_reports():
        return render_template("performance_reports.html")

    @app.route("/create_user", methods=['GET', 'POST'])
    def create_user():
        form = CreateUserForm()
        if form.validate_on_submit():
            try:
                # Create a new user in Supabase authentication
                auth_response = app.supabase.auth.sign_up({
                    "email": form.email.data,
                    "password": form.password.data
                })
                if not auth_response.user:
                    raise Exception("Supabase Auth: User creation failed")

                # store auth user id
                auth_user_id = auth_response.user.id
                # Hash user password before storing
                password_hash = bcrypt.generate_password_hash(
                    form.password.data).decode('utf-8')

                # Debug: Print the data to be sent to the RPC
                print(
                    f"Creating user with auth_user_id: {auth_user_id}, username: {form.username.data}")

                # Generate UUID
                user_id = str(uuid.uuid4())

                # Call the SQL RPC function to insert into the users table
                response = app.supabase.rpc('create_user', {
                    'p_user_id': user_id,
                    'p_employee_id': form.employee_id.data,
                    'p_username': form.username.data,
                    'p_password': password_hash,
                    'p_email': form.email.data,
                    'p_role': form.role.data,
                    'p_name': form.name.data,
                    'p_status': form.status.data,
                    'p_auth_user_id': auth_user_id
                }).execute()

                # Debug: Check if the RPC call was successful
                print(f"RPC response: {response}")

                if response.status_code != 200:
                    raise Exception("RPC function failed to execute")

                flash("User created successfully!", "success")
                return redirect(url_for('dashboard'))

            except Exception as e:
                flash(f"Error: {str(e)}", "danger")
                return render_template('create_user.html', form=form)

        return render_template('create_user.html', form=form)

    @app.route('/accept_user', methods=['GET'])
    def accept_user():
        auth_user_id = request.args.get('auth_user_id')

        result = app.supabase.table('users').select(
            '*').eq('auth_user_id', auth_user_id).execute()

        if not result.data:
            flash("Invalid or expired invitation link.", "danger")
            return redirect(url_for('login'))

        user_info = result.data[0]

        try:
            auth_response = app.supabase.auth.sign_up({
                "email": user_info['email'],
                "password": user_info['password']
            })

            if not auth_response or auth_response.user is None:
                flash("Failed to create user in supabase authentication.", 'danger')
                return redirect(url_for('login'))

            app.supabase.table('users').update({
                'status': 'approved',
                'updated_at': 'now()',
                'auth_user_id': auth_response.user['id']
            }).eq('auth_user_id', auth_user_id).execute()

            flash("Invitation accepted! Your account is now active.", 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            flash(f"Error occurred: {str(e)}", "danger")
            return redirect(url_for('login'))

    @app.route("/start_performance_review", methods=["POST"])
    def start_performance_review():
        if "user" not in session or session["user"]["role"] != "SuperUser":
            return jsonify({"error": "Unauthorized"}), 403

        send_notifications_to_all("Performance reviews are starting!")
        return jsonify({"message": "Performance review process started"}), 200

    @app.route("/notify_managers", methods=["POST"])
    def notify_managers():
        if "user" not in session or session["user"]["role"] != "SuperUser":
            return jsonify({"error": "Unauthorized"}), 403

        send_notifications_to_role(
            "Manager", "Please start the performance reviews.")
        return jsonify({"message": "Managers notified"}), 200

    @app.route("/submit_review", methods=["POST"])
    def submit_review():
        if "user" not in session or session["user"]["role"] != "Manager":
            return jsonify({"error": "Unauthorized"}), 403

        employee_id = request.form.get("employee_id")
        business_result = request.form.get("business_result")
        individual_result = request.form.get("individual_result")
        safety_result = request.form.get("safety_result")
        bonus_payout = request.form.get("bonus_payout")

        app.supabase.table("performance_reviews").insert({
            "employee_id": employee_id,
            "business_result": business_result,
            "individual_result": individual_result,
            "safety_result": safety_result,
            "bonus_payout": bonus_payout,
            "evaluation_date": datetime.datetime.now()
        }).execute()

        send_notification_to_employee(
            employee_id, "Your performance review is complete.")

        return jsonify({"message": "Review submitted"}), 200

    @app.route("/complete_performance_review", methods=["POST"])
    def complete_performance_review():
        if "user" not in session or session["user"]["role"] != "SuperUser":
            return jsonify({"error": "Unauthorized"}), 403

        send_notifications_to_all("Performance reviews are complete!")
        return jsonify({"message": "Performance review process completed"}), 200

    @app.route("/workflows", methods=["GET", "POST"])
    def workflows():
        if "user" not in session or session["user"]["role"] != "SuperUser":
            flash("Unauthorized access.", "danger")
            return redirect(url_for("dashboard"))
    
        form = NotificationForm()  # Initialize your form here
        if form.validate_on_submit():
           # Process form submission here if needed
           pass

        return render_template("workflows.html", form=form)

    @app.route("/employee_position")
    def employee_position():
        return render_template('employee_position.html')

    @app.route("/employee_profile")
    def employee_profile():
        return render_template('employee_position.html')

    @app.route("/trigger_workflow", methods=["POST"])
    def trigger_workflow():
        form = NotificationForm()
        if "user" not in session or session["user"]["role"] != "SuperUser":
            return jsonify({"error": "Unauthorized"}), 403

        if form.validate_on_submit():
            notification_message = form.notification_message.data
            send_notifications_to_all(app.supabase, notification_message)
            flash("Performance Review Workflow triggered.", "success")
        return redirect(url_for("workflows"))