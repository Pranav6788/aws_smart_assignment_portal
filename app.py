from flask import Flask, render_template, request, redirect, url_for, flash
import boto3
import pymysql
from datetime import timedelta # Used for presigned URL expiration

app = Flask(__name__)

# --- Configuration & Global Data ---
S3_BUCKET = "assignment-submissions-portal"
s3 = boto3.client('s3')

# Define a list of faculties for the dropdowns
FACULTY_LIST = [
    "Dr. Anya Sharma (CS)", 
    "Prof. Ben Carter (Math)", 
    "Ms. Clara Diaz (Physics)",
    "Mr. David Lee (History)"
]

# RDS Configuration
# NOTE: Using a connection pool or ORM is better for production.
db_config = {
    "host": "sasep-db.c1smok8qmm0y.ap-south-1.rds.amazonaws.com",
    "user": "admin",
    "password": "pranavyuv123#",
    "database": "assignments"
}

def get_db_connection():
    """Establishes a new database connection."""
    return pymysql.connect(**db_config)

# --- S3 Helper Function ---
def create_presigned_url(bucket_name, object_name, expiration=3600):
    """Generate a presigned URL to share an S3 object."""
    try:
        response = s3.generate_presigned_url('get_object',
                                             Params={'Bucket': bucket_name,
                                                     'Key': object_name},
                                             ExpiresIn=expiration)
    except Exception as e:
        print(f"Error generating presigned URL for {object_name}: {e}")
        return None
    return response

# --- Routes ---

@app.route('/')
def landing_page():
    """Renders the main landing page for role selection (Student or Faculty)."""
    return render_template('index.html')

@app.route('/studentView')
def student_upload_form():
    """Renders the dedicated upload form page with the faculty list."""
    return render_template('studentView.html', faculty_list=FACULTY_LIST)

@app.route('/upload', methods=['POST'])
def upload():
    """Handles the file upload and database logging, organized by faculty."""
    conn = None
    try:
        file = request.files.get('file')
        student_name = request.form.get('student_name')
        faculty_name = request.form.get('faculty_name') # New field

        if not file or not student_name or not faculty_name:
             return "Missing file, student name, or faculty selection.", 400

        # Define the S3 key structure: submissions/<faculty>/<student>_<filename>
        s3_key = f"submissions/{faculty_name}/{student_name}_{file.filename}"
        s3.upload_fileobj(file, S3_BUCKET, s3_key)
        
        # Log upload in RDS (assuming submissions table has columns: student_name, faculty_name, filename, s3_key, marks, remarks, uploaded_at)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # marks and remarks are initially NULL
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
def faculty():
    """Displays the list of submissions, filtered by selected faculty."""
    conn = None
    try:
        selected_faculty = request.args.get('faculty_name')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # SQL to fetch all necessary columns
        base_sql = "SELECT id, student_name, faculty_name, filename, s3_key, marks, remarks, uploaded_at FROM submissions"
        
        if selected_faculty and selected_faculty != 'All':
            # Filter by the selected faculty
            sql = f"{base_sql} WHERE faculty_name = %s ORDER BY uploaded_at DESC"
            cursor.execute(sql, (selected_faculty,))
        else:
            # Show all submissions if no filter is applied
            sql = f"{base_sql} ORDER BY uploaded_at DESC"
            cursor.execute(sql)

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
            'faculty.html', 
            submissions=submissions, 
            faculty_list=FACULTY_LIST, 
            selected_faculty=selected_faculty
        )
    except Exception as e:
        print(f"An error occurred during faculty view: {e}")
        return f"Could not retrieve submissions: {e}", 500
    finally:
        if conn:
            conn.close()

@app.route('/update_submission', methods=['POST'])
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
        
        # Optionally, you might want to redirect back to the filtered view
        current_faculty = request.form.get('current_faculty', 'All')
        return redirect(url_for('faculty', faculty_name=current_faculty))
        
    except Exception as e:
        print(f"An error occurred during update: {e}")
        return f"An internal error occurred during update: {e}", 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
