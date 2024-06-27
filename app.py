'''
i have list of predefine users and admins,
where user name is [user1, user2, user3, user4, user5]
and admin name is [admin]
the password for all users are same with the username and admin password is admin

user page:
after login, user can only upload excel
user can download pdf files, which is allocated to them
user can change his own password but not user name
user can logout

admin page:
admin can upload pdf and choose the user to allocate the pdf file,
which means the pdf file will be available to that user only

admin can download excel files, which is uploaded by user,
excel files are arranged in the group of corresponding user

i want backend code in python flask, and front end in html, css, js
I upload some images for reference


'''

from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for, render_template_string
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Define directories for file uploads
UPLOAD_FOLDER = 'uploads'
PDF_FOLDER = os.path.join(UPLOAD_FOLDER, 'pdf')
EXCEL_FOLDER = os.path.join(UPLOAD_FOLDER, 'excel')

# Predefined users and admins
users = {'user1': 'user1', 'user2': 'user2', 'user3': 'user3', 'user4': 'user4', 'user5': 'user5'}
admins = {'admin': 'admin'}

# Create directories for users and admins
for user in users.keys():
    os.makedirs(os.path.join(EXCEL_FOLDER, user), exist_ok=True)
    os.makedirs(os.path.join(PDF_FOLDER, user), exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Helper function to check login
def check_login(username, password):
    if username in users and users[username] == password:
        return 'user'
    elif username in admins and admins[username] == password:
        return 'admin'
    return None

@app.route('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = check_login(username, password)
        if role:
            session['username'] = username
            session['role'] = role
            return redirect(url_for(f'{role}_dashboard'))
        return 'Invalid credentials', 401
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login</title>
    </head>
    <body>
        <h1>Login</h1>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    ''')


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))


@app.route('/user/dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    user_folder = os.path.join(EXCEL_FOLDER, session['username'])
    pdf_folder = os.path.join(PDF_FOLDER, session['username'])

    pdf_files = os.listdir(pdf_folder)

    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.endswith('.xlsx'):
            filename = secure_filename(file.filename)
            file.save(os.path.join(user_folder, filename))

    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>User Dashboard</title>
    </head>
    <body>
        <h1>Upload Excel</h1>
        <form action="/user/dashboard" method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept=".xlsx">
            <button type="submit">Upload</button>
        </form>
        <h1>Download PDF</h1>
        <ul>
        {% for file in pdf_files %}
            <li><a href="/download/{{ session['username'] }}/{{ file }}">{{ file }}</a></li>
        {% endfor %}
        </ul>
        <a href="/change_password">Change Password</a>
        <a href="/logout">Logout</a>
    </body>
    </html>
    ''', pdf_files=pdf_files)


@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        user = request.form['user']
        user_folder = os.path.join(PDF_FOLDER, user)

        file = request.files['file']
        if file and file.filename.endswith('.pdf'):
            filename = secure_filename(file.filename)
            file.save(os.path.join(user_folder, filename))

    user_files = {user: os.listdir(os.path.join(EXCEL_FOLDER, user)) for user in users.keys()}

    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Dashboard</title>
    </head>
    <body>
        <h1>Upload PDF</h1>
        <form action="/admin/dashboard" method="post" enctype="multipart/form-data">
            <select name="user">
                <option value="user1">User1</option>
                <option value="user2">User2</option>
                <option value="user3">User3</option>
                <option value="user4">User4</option>
                <option value="user5">User5</option>
            </select>
            <input type="file" name="file" accept=".pdf">
            <button type="submit">Upload</button>
        </form>
        <h1>Download Excel</h1>
        {% for user, files in user_files.items() %}
            <h2>{{ user }}</h2>
            <ul>
            {% for file in files %}
                <li><a href="/download/{{ user }}/{{ file }}">{{ file }}</a></li>
            {% endfor %}
            </ul>
        {% endfor %}
        <a href="/logout">Logout</a>
    </body>
    </html>
    ''', user_files=user_files)


@app.route('/download/<user>/<filename>')
def download_file(user, filename):

    if '.pdf' in filename:
        user_folder = os.path.join(PDF_FOLDER, user)
    else:
        user_folder = os.path.join(EXCEL_FOLDER, user)
    print('user_folder', user_folder)
    print('filename', filename)
    if user in users:
        return send_from_directory(user_folder, filename)
    return 'File not found', 404


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        username = session['username']

        if session['role'] == 'user' and users[username] == current_password:
            users[username] = new_password
            return 'Password changed successfully'
        elif session['role'] == 'admin' and admins[username] == current_password:
            admins[username] = new_password
            return 'Password changed successfully'
        return 'Invalid current password', 401

    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Change Password</title>
    </head>
    <body>
        <h1>Change Password</h1>
        <form action="/change_password" method="post">
            <input type="password" name="current_password" placeholder="Current Password">
            <input type="password" name="new_password" placeholder="New Password">
            <button type="submit">Change</button>
        </form>
        <a href="/user/dashboard">Back to Dashboard</a>
        <a href="/logout">Logout</a>
    </body>
    </html>
    ''')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)
