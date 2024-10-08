from flask import Flask, request, render_template, make_response, redirect, url_for, flash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from werkzeug.security import generate_password_hash, check_password_hash
import os
import time
from flask_sqlalchemy import SQLAlchemy
from models import db, User, create_user

app = Flask(__name__)

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

    def encrypt(self, data):
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(self.pad(data.encode())))

    def decrypt(self, data):
        raw = b64decode(data)
        cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return self.unpad(cipher.decrypt(raw[AES.block_size:])).decode()


cipher = AESCipher(app.secret_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash("You missed a spot you silly goose.")
            return redirect(url_for('login'))

        # Use the get_by_username method to fetch user
        user = User.get_by_username(username)
        if not user or not user.check_password(password):
            flash("Invalid credentials")
            return redirect(url_for('login'))

        # Prepare the session cookie
        cookie_data = f"username={username}&admin=0"
        encrypted_cookie = cipher.encrypt(cookie_data)
        encrypted_cookie_str = encrypted_cookie.decode()  # Decode to string

        resp = make_response(redirect(url_for('profile')))
        resp.set_cookie('session', encrypted_cookie_str)  # Set cookie as a string
        return resp
    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate form inputs
        if not username or not password:
            flash("You missed a spot you silly goose.")
            return redirect(url_for('register'))

        # Disallow admin username registration
        if username.lower() == 'admin':
            flash("Nice try, but you can't register as admin.")
            return redirect(url_for('register'))

        # Check if user already exists and create user using create_user function
        if User.get_by_username(username):
            flash("User already exists")
            return redirect(url_for('register'))
        
        user = create_user(db, username, password)
        if isinstance(user, str):  # If there was an error during user creation
            flash(user)  # Display the error
        else:
            flash("Registration successful. Please login.")
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