from flask import Flask, render_template, request, redirect, url_for
import boto3
import pymysql

app = Flask(__name__)

# S3 Configuration
S3_BUCKET = "assignment-submissions-portal"
s3 = boto3.client('s3')

# RDS Configuration
db = pymysql.connect(
    host="sasep-db.c1smok8qmm0y.ap-south-1.rds.amazonaws.com",
    user="admin",
    password="pranavyuv123#",
    database="assignments"
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    student_name = request.form['student_name']

    if file:
        s3.upload_fileobj(file, S3_BUCKET, f"student/{student_name}/{file.filename}")
        
        # Log upload in RDS
        cursor = db.cursor()
        cursor.execute("INSERT INTO submissions (student, filename) VALUES (%s, %s)", (student_name, file.filename))
        db.commit()

        return render_template('success.html', student_name=student_name, filename=file.filename)
    return "No file uploaded", 400

@app.route('/faculty')
def faculty():
    cursor = db.cursor()
    cursor.execute("SELECT * FROM submissions")
    results = cursor.fetchall()
    return render_template('faculty.html', submissions=results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
