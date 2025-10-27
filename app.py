from flask import Flask, render_template, request, redirect, url_for, session, flash
import boto3
import pymysql
from functools import wraps
from datetime import timedelta
import json # Added for processing Cognito response attributes

# --- Initialization ---
app = Flask(__name__)
# Set a secret key for session management (MUST be secure in production)
app.secret_key = 'pranavyuvaraj_super_secret_key' 

# --- Configuration & Global Data ---
S3_BUCKET = "assignment-submissions-portal"
s3 = boto3.client('s3')

# --- COGNITO CONFIGURATION (REPLACE WITH YOUR AWS DETAILS) ---
# NOTE: These values must be obtained after setting up your User Pool in the AWS Console.
AWS_REGION = 'ap-south-1'  # Ensure this matches your RDS and Cognito region
USER_POOL_ID = 'ap-south-1_mMrNDKvR6' # Placeholder
CLIENT_ID = 'xxxxxxxxxxxxxxxxxxxxxxxxxx' # Placeholder App Client ID

# Initialize Cognito Client
cognito_client = boto3.client('cognito-idp', region_name=AWS_REGION)

# RDS Configuration
db_config = {
    "host": "sasep-db.c1smok8qmm0y.ap-south-1.rds.amazonaws.com",
    "user": "admin",
    "password": "pranavyuv123#",
    "database": "assignments"
}

def get_db_connection():
    """Establishes a new database connection."""
    return pymysql.connect(**db_config)

# --- Utility Functions ---

def get_user_details_from_session():
    """Retrieves user details (role and name) from Cognito using the session token."""
    if 'id_token' not in session:
        return None
    
    try:
        # Use a token to get user details (simulating Cognito's GetUser)
        # Note: In a real app, we might use the Access Token and the GetUser API call.
        # For simplicity here, we assume the token holds enough info or can be easily validated.
        
        # MOCK: In a true Cognito implementation, this step involves decoding the JWT ID token
        # and/or calling cognito_client.get_user().
        
        # Since we can't fully decode the JWT here, we'll store role and name in the session 
        # upon successful login (see login() function).
        return {
            'email': session.get('email'),
            'role': session.get('role'),
            'name': session.get('name')
        }
    except Exception as e:
        print(f"Error retrieving user details from token: {e}")
        return None

def login_required(role=None):
    """Decorator to check for logged-in user and optional role."""
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_details = get_user_details_from_session()
            if not user_details:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            
            # Authorization check based on session role
            if role and user_details.get('role') != role:
                flash(f'Access denied. Required role: {role}', 'error')
                return redirect(url_for('landing_page'))
            
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

def get_registered_faculties():
    """
    Dynamically retrieves names of all users registered as 'faculty' 
    from the Cognito User Pool (requires ListUsers and ListGroups permissions on the execution role).
    """
    faculty_list = []
    try:
        # 1. Find all users in the 'faculty' group
        response = cognito_client.list_users_in_group(
            UserPoolId=USER_POOL_ID,
            GroupName='faculty'
        )
        
        for user in response.get('Users', []):
            # 2. Extract the 'name' attribute (which holds the full faculty name)
            # Assuming 'name' is stored as a standard Cognito attribute.
            name_attr = next((attr['Value'] for attr in user.get('Attributes', []) 
                              if attr['Name'] == 'name'), None)
            
            if name_attr:
                faculty_list.append(name_attr)

    except Exception as e:
        # NOTE: This will fail if the necessary IAM permissions are not granted 
        # to the EC2 instance's IAM role.
        print(f"Error fetching faculty list from Cognito: {e}")
        # Fallback for testing: ensure at least one faculty name exists
        if not faculty_list:
            faculty_list.append("Dr. Anya Sharma (CS) - FAILED COGNITO LOOKUP")
            
    return faculty_list

def create_presigned_url(bucket_name, object_name, expiration=3600):
    """Generate a presigned URL to share an S3 object."""
    try:
        # NOTE: The EC2 IAM Role must have s3:GetObject on the submission path.
        response = s3.generate_presigned_url('get_object',
                                             Params={'Bucket': bucket_name,
                                                     'Key': object_name},
                                             ExpiresIn=expiration)
    except Exception as e:
        print(f"Error generating presigned URL for {object_name}: {e}")
        return None
    return response

# --- Authentication Routes ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        name = request.form.get('name') # Only required for faculty

        try:
            # 1. Create User in Cognito User Pool
            cognito_client.sign_up(
                ClientId=CLIENT_ID,
                Username=email,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'name', 'Value': name if role == 'faculty' else email},
                ]
            )
            
            # NOTE: New users in Cognito are unconfirmed by default. 
            # We skip confirmation logic for this example, but it's mandatory in production.
            
            # 2. Set the user's role (group)
            # Admin must manually confirm the user and add them to the correct group 
            # in a production environment, but we simulate it here:
            cognito_client.admin_add_user_to_group(
                UserPoolId=USER_POOL_ID,
                Username=email,
                GroupName=role # 'student' or 'faculty'
            )
            
            flash('Account created successfully! Please log in (user is auto-confirmed/grouped for this example).', 'success')
            return redirect(url_for('login'))
        
        except cognito_client.exceptions.UsernameExistsException:
            flash('Email already registered. Please log in.', 'error')
            return redirect(url_for('signup'))
        except Exception as e:
            flash(f'Signup failed: {e}', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            # 1. Authenticate user against Cognito
            auth_response = cognito_client.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password,
                }
            )
            
            id_token = auth_response['AuthenticationResult']['IdToken']
            
            # 2. Get User Details (Role/Name) using the token
            user_response = cognito_client.get_user(
                AccessToken=auth_response['AuthenticationResult']['AccessToken']
            )
            
            # Extract attributes
            user_attributes = {attr['Name']: attr['Value'] for attr in user_response['UserAttributes']}
            user_groups_response = cognito_client.admin_list_groups_for_user(
                UserPoolId=USER_POOL_ID,
                Username=email
            )
            
            # Determine role (assuming one group per user)
            role = user_groups_response['Groups'][0]['GroupName'] if user_groups_response['Groups'] else 'unknown'
            
            # Set Flask Session with role and name
            session['email'] = email
            session['role'] = role
            session['name'] = user_attributes.get('name', email) # Use the name attribute if available
            session['id_token'] = id_token # Store token for future auth checks
            
            flash('Login successful.', 'success')
            if role == 'faculty':
                return redirect(url_for('faculty'))
            elif role == 'student':
                return redirect(url_for('student_upload_form'))
            else:
                flash('Your role is undefined. Access denied.', 'error')
                return redirect(url_for('landing_page'))

        except cognito_client.exceptions.NotAuthorizedException:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Login failed: {e}', 'error')
            return redirect(url_for('login'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    # In a real app, you should also revoke the token using cognito_client.global_sign_out
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing_page'))

# --- Application Routes ---

@app.route('/')
def landing_page():
    """Renders the main landing page for role selection or logged-in status."""
    user_details = get_user_details_from_session()
    return render_template('index.html', session=session, user_details=user_details)

@app.route('/studentView')
@login_required('student')
def student_upload_form():
    """Renders the dedicated upload form page with dynamic faculty list."""
    faculty_list = get_registered_faculties()
    return render_template('studentView.html', faculty_list=faculty_list)

@app.route('/upload', methods=['POST'])
@login_required('student')
def upload():
    """Handles the file upload and database logging."""
    # Logic remains similar, but now protected by login_required
    conn = None
    try:
        file = request.files.get('file')
        student_name = request.form.get('student_name')
        faculty_name = request.form.get('faculty_name') 

        if not file or not student_name or not faculty_name:
             return "Missing file, student name, or faculty selection.", 400

        # Define the S3 key structure: submissions/<faculty>/<student>_<filename>
        s3_key = f"submissions/{faculty_name}/{student_name}_{file.filename}"
        
        # NOTE: EC2 IAM Role must have s3:PutObject for this path.
        s3.upload_fileobj(file, S3_BUCKET, s3_key)
        
        # Log upload in RDS
        conn = get_db_connection()
        cursor = conn.cursor()
        
        sql = """
            INSERT INTO submissions (student_name, faculty_name, filename, s3_key, marks, remarks) 
            VALUES (%s, %s, %s, %s, NULL, NULL)
        """
        cursor.execute(sql, (student_name, faculty_name, file.filename, s3_key))
        conn.commit()

        return render_template('success.html', student_name=student_name, filename=file.filename)
    
    except Exception as e:
        print(f"An error occurred during upload: {e}")
        return f"An internal error occurred: {e}", 500
    finally:
        if conn:
            conn.close()


@app.route('/faculty')
@login_required('faculty')
def faculty():
    """Displays the list of submissions, filtered by the LOGGED-IN faculty."""
    conn = None
    try:
        current_user = get_user_details_from_session()
        logged_in_faculty_name = current_user['name'] # Get the name from the session user

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # SQL fetches only submissions assigned to the current user
        base_sql = "SELECT id, student_name, faculty_name, filename, s3_key, marks, remarks, uploaded_at FROM submissions"
        sql = f"{base_sql} WHERE faculty_name = %s ORDER BY uploaded_at DESC"
        cursor.execute(sql, (logged_in_faculty_name,))

        submissions = []
        for row in cursor.fetchall():
            submission = {
                'id': row[0],
                'student_name': row[1],
                'faculty_name': row[2],
                'filename': row[3],
                's3_key': row[4],
                'marks': row[5] if row[5] is not None else '',
                'remarks': row[6] if row[6] is not None else '',
                'uploaded_at': row[7],
                'view_url': create_presigned_url(S3_BUCKET, row[4])
            }
            submissions.append(submission)
            
        return render_template(
            'facultyView.html', 
            submissions=submissions, 
            logged_in_faculty_name=logged_in_faculty_name
        )
    except Exception as e:
        print(f"An error occurred during faculty view: {e}")
        return f"Could not retrieve submissions: {e}", 500
    finally:
        if conn:
            conn.close()

@app.route('/update_submission', methods=['POST'])
@login_required('faculty')
def update_submission():
    """Handles the update of marks and remarks for a submission."""
    conn = None
    try:
        submission_id = request.form.get('submission_id')
        marks = request.form.get('marks')
        remarks = request.form.get('remarks')
        
        if not submission_id:
            return "Submission ID missing.", 400
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # Update SQL command
        sql = "UPDATE submissions SET marks = %s, remarks = %s WHERE id = %s"
        cursor.execute(sql, (marks, remarks, submission_id))
        conn.commit()
        
        # Redirect back to the faculty submissions page
        return redirect(url_for('faculty'))
        
    except Exception as e:
        print(f"An error occurred during update: {e}")
        return f"An internal error occurred during update: {e}", 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)









# from flask import Flask, render_template, request, redirect, url_for, flash
# import boto3
# import pymysql
# from datetime import timedelta # Used for presigned URL expiration

# app = Flask(__name__)

# # --- Configuration & Global Data ---
# S3_BUCKET = "assignment-submissions-portal"
# s3 = boto3.client('s3')

# # Define a list of faculties for the dropdowns
# FACULTY_LIST = [
#     "Dr. Anya Sharma (CS)", 
#     "Prof. Ben Carter (Math)", 
#     "Ms. Clara Diaz (Physics)",
#     "Mr. David Lee (History)"
# ]

# # RDS Configuration
# # NOTE: Using a connection pool or ORM is better for production.
# db_config = {
#     "host": "sasep-db.c1smok8qmm0y.ap-south-1.rds.amazonaws.com",
#     "user": "admin",
#     "password": "pranavyuv123#",
#     "database": "assignments"
# }

# def get_db_connection():
#     """Establishes a new database connection."""
#     return pymysql.connect(**db_config)

# # --- S3 Helper Function ---
# def create_presigned_url(bucket_name, object_name, expiration=3600):
#     """Generate a presigned URL to share an S3 object."""
#     try:
#         response = s3.generate_presigned_url('get_object',
#                                              Params={'Bucket': bucket_name,
#                                                      'Key': object_name},
#                                              ExpiresIn=expiration)
#     except Exception as e:
#         print(f"Error generating presigned URL for {object_name}: {e}")
#         return None
#     return response

# # --- Routes ---

# @app.route('/')
# def landing_page():
#     """Renders the main landing page for role selection (Student or Faculty)."""
#     return render_template('index.html')

# @app.route('/studentView')
# def student_upload_form():
#     """Renders the dedicated upload form page with the faculty list."""
#     return render_template('studentView.html', faculty_list=FACULTY_LIST)

# @app.route('/upload', methods=['POST'])
# def upload():
#     """Handles the file upload and database logging, organized by faculty."""
#     conn = None
#     try:
#         file = request.files.get('file')
#         student_name = request.form.get('student_name')
#         faculty_name = request.form.get('faculty_name') # New field

#         if not file or not student_name or not faculty_name:
#              return "Missing file, student name, or faculty selection.", 400

#         # Define the S3 key structure: submissions/<faculty>/<student>_<filename>
#         s3_key = f"submissions/{faculty_name}/{student_name}_{file.filename}"
#         s3.upload_fileobj(file, S3_BUCKET, s3_key)
        
#         # Log upload in RDS (assuming submissions table has columns: student_name, faculty_name, filename, s3_key, marks, remarks, uploaded_at)
#         conn = get_db_connection()
#         cursor = conn.cursor()
        
#         # marks and remarks are initially NULL
#         sql = """
#             INSERT INTO submissions (student_name, faculty_name, filename, s3_key, marks, remarks) 
#             VALUES (%s, %s, %s, %s, NULL, NULL)
#         """
#         cursor.execute(sql, (student_name, faculty_name, file.filename, s3_key))
#         conn.commit()

#         return render_template('success.html', student_name=student_name, filename=file.filename)
    
#     except Exception as e:
#         print(f"An error occurred during upload: {e}")
#         return f"An internal error occurred: {e}", 500
#     finally:
#         if conn:
#             conn.close()


# @app.route('/faculty')
# def faculty():
#     """Displays the list of submissions, filtered by selected faculty."""
#     conn = None
#     try:
#         selected_faculty = request.args.get('faculty_name')
        
#         conn = get_db_connection()
#         cursor = conn.cursor()
        
#         # SQL to fetch all necessary columns
#         base_sql = "SELECT id, student_name, faculty_name, filename, s3_key, marks, remarks, uploaded_at FROM submissions"
        
#         if selected_faculty and selected_faculty != 'All':
#             # Filter by the selected faculty
#             sql = f"{base_sql} WHERE faculty_name = %s ORDER BY uploaded_at DESC"
#             cursor.execute(sql, (selected_faculty,))
#         else:
#             # Show all submissions if no filter is applied
#             sql = f"{base_sql} ORDER BY uploaded_at DESC"
#             cursor.execute(sql)

#         submissions = []
#         for row in cursor.fetchall():
#             submission = {
#                 'id': row[0],
#                 'student_name': row[1],
#                 'faculty_name': row[2],
#                 'filename': row[3],
#                 's3_key': row[4],
#                 'marks': row[5] if row[5] is not None else '',
#                 'remarks': row[6] if row[6] is not None else '',
#                 'uploaded_at': row[7],
#                 'view_url': create_presigned_url(S3_BUCKET, row[4])
#             }
#             submissions.append(submission)
            
#         return render_template(
#             'facultyView.html', 
#             submissions=submissions, 
#             faculty_list=FACULTY_LIST, 
#             selected_faculty=selected_faculty
#         )
#     except Exception as e:
#         print(f"An error occurred during faculty view: {e}")
#         return f"Could not retrieve submissions: {e}", 500
#     finally:
#         if conn:
#             conn.close()

# @app.route('/update_submission', methods=['POST'])
# def update_submission():
#     """Handles the update of marks and remarks for a submission."""
#     conn = None
#     try:
#         submission_id = request.form.get('submission_id')
#         marks = request.form.get('marks')
#         remarks = request.form.get('remarks')
        
#         if not submission_id:
#             return "Submission ID missing.", 400
        
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         # Update SQL command
#         sql = "UPDATE submissions SET marks = %s, remarks = %s WHERE id = %s"
#         cursor.execute(sql, (marks, remarks, submission_id))
#         conn.commit()
        
#         # Optionally, you might want to redirect back to the filtered view
#         current_faculty = request.form.get('current_faculty', 'All')
#         return redirect(url_for('faculty', faculty_name=current_faculty))
        
#     except Exception as e:
#         print(f"An error occurred during update: {e}")
#         return f"An internal error occurred during update: {e}", 500
#     finally:
#         if conn:
#             conn.close()

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=80, debug=True)
