from flask import Flask, request, render_template, make_response, redirect, url_for, flash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from models import db, User, create_user

app = Flask(__name__)
TIME = lambda fmt:  datetime.now().strftime(fmt)
TIME_FMT = "%Y-%m-%d %H:%M:%S"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
app.secret_key = os.urandom(16)

FLAG = open('flag.txt').read().strip()

    
with app.app_context():
    db.create_all()

class AESCipher:
    def __init__(self, key):
        self.key = key
        self.pad = lambda x: pad(x, AES.block_size)
        self.unpad = lambda x: unpad(x, AES.block_size)
        self.bs = AES.block_size
    def encrypt(self, data):
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(self.pad(data.encode())))

    def decrypt(self, data):
        raw = b64decode(data)
        iv = raw[:self.bs]
        ct = raw[self.bs:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        return self.unpad(cipher.decrypt(ct)).decode()


cipher = AESCipher(app.secret_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Received {username}:{password} from {request.remote_addr}")
        # Check for empty fields
        if not username or not password:
            flash("You missed a spot you silly goose.", "error")
            return redirect(url_for('login'))

        # Fetch user by username
        user = User.get_by_username(username)
        if not user:
            flash("User not found. Please register first.", "error")
            return redirect(url_for('login'))

        # Check if the password is correct
        if not user.check_password(password):
            flash("Invalid password. Please try again.", "error")
            return redirect(url_for('login'))

        # Prepare the session cookie if login is successful
        cookie_data = f"username={username}&admin=0"
        encrypted_cookie = cipher.encrypt(cookie_data)
        encrypted_cookie_str = encrypted_cookie.decode()  # Decode to string

        # Set the session cookie and redirect to profile
        resp = make_response(redirect(url_for('profile')))
        resp.set_cookie('session', encrypted_cookie_str)  # Set cookie as a string

        # Flash a success message
        flash("Login successful!", "success")
        return resp

    return render_template('login.html')




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate form inputs
        if not username or not password:
            flash("You missed a spot you silly goose.", "error")
            return redirect(url_for('register'))

        # Disallow registration with 'admin' username
        if username.lower() == 'admin':
            flash("Nice try, but you can't register as admin.", "error")
            return redirect(url_for('register'))

        # Check if the user already exists
        if User.get_by_username(username):
            flash("User already exists", "error")
            return redirect(url_for('register'))

        # Create user using create_user function
        user = create_user(db, username, password)
        if isinstance(user, str):  # If there was an error during user creation
            flash(user, "error")  # Display the error
        else:
            flash("Registration successful. Please login.", "success")
            return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/profile')
def profile():
    encrypted_cookie = request.cookies.get('session')
    if not encrypted_cookie:
        return redirect(url_for('login'))
    try:
        cookie_data = cipher.decrypt(encrypted_cookie)
        if 'admin=1' in cookie_data:
            return redirect(url_for('flag'))
        username = cookie_data.split('&')[0].split('=')[1]
        return render_template('profile.html', username=username)
    except:
        return redirect(url_for('login'))


@app.route('/flag')
def flag():
    encrypted_cookie = request.cookies.get('session')
    if not encrypted_cookie:
        return redirect(url_for('login'))
    try:
        cookie_data = cipher.decrypt(encrypted_cookie)
        if 'admin=1' in cookie_data:
            return render_template('flag.html', flag=FLAG)
        else:
            return "Access denied. Admin privileges required.", 403
    except:
        return redirect(url_for('login'))




if __name__ == '__main__':
    app.run(debug=True)