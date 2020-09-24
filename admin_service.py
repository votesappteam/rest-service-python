import configparser
import datetime
import math
import random
# import json
import re
import string

from flask import Flask, render_template, request, redirect, url_for, session, flash
# import pymysql
from flask_pymongo import PyMongo
from flask_sqlalchemy import SQLAlchemy
from source.mail_service import sendemail
app = Flask(__name__)
#app = Flask(_name__, template_folder='templates_bk')

#Read the config file
configFile = '/var/www/votesapp-rest/config.ini'

config = configparser.ConfigParser()
config.read(configFile)


#PySQL configurations

userpass = config['MYSQLDB']['USERPASS']
basedir  = '127.0.0.1'
dbname  = '/votesapp_db'
socket = config['MYSQLDB']['SOCKET']
dbname = dbname + socket


app.config['SECRET_KEY'] = config['SECURITY']['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = userpass + basedir + dbname
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload file
UPLOAD_FOLDER = '/var/www/votesapp-rest/nsfw-images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

mongo_connect_str = 'mongodb://localhost:27017/'
mongo_db ='votesapp_db'
#Mongo configuration
app.config['MONGO_DBNAME'] = 'votesapp_db'
app.config['MONGO_URI'] = mongo_connect_str+mongo_db
mongo = PyMongo(app)

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
session = {}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db = SQLAlchemy(app)

class web_user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150))
    created_by = db.Column(db.String(50))
    role = db.Column(db.String(15))
    empid = db.Column(db.String(45))
    active = db.Column(db.Boolean)
    created_dt = db.Column(db.DateTime, default=datetime.datetime.utcnow())

class web_user_otp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer)
    otp = db.Column(db.Integer)
    requested_dt = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    requested_by = db.Column(db.String(45))
    otp_used = db.Column(db.Boolean)
    otp_expired = db.Column(db.Boolean)

class new_brand_requests(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    brandtype = db.Column(db.String(45))
    branddescription = db.Column(db.String(300))
    brandname = db.Column(db.String(70))
    brandcategory = db.Column(db.String(45))
    brandemail = db.Column(db.String(150))
    brandwebpage = db.Column(db.String(250))
    active = db.Column(db.Boolean)
    brand_id = db.Column(db.String(45))
    claimed = db.Column(db.Boolean)
    posted_by_dt = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    status_change_dt = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    posted_by_user = db.Column(db.String(300))
    decision = db.Column(db.String(15))
    decision_reason = db.Column(db.String(100))
    modified_by = db.Column(db.String(155))


def generate_otp():
    # Declare a digits variable
    # which stores all digits
    digits = "0123456789"
    OTP = ""

    # length of password can be chaged
    # by changing value in range
    for i in range(8):
        OTP += digits[math.floor(random.random() * 10)]

    return OTP

def generate_request_id():
    ri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    return ri
#Reference --> https://codeshack.io/login-system-python-flask-mysql/
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'email' in request.form:
        # Create variables for easy access
        email = request.form['email']
        print(email)
        # Check if account exists using MySQL
        #email = username+"@votesapp.co.in"


        if email:
            active = web_user.query.filter(web_user.email == email).first()

            if active:
                if active.active==False:
                    return 'Account is not active'
                # Create session data, we can access this data in other routes

                session['id'] = active.id
                session['email'] = active.email
                otp = int(generate_otp())
                request_id = generate_request_id()
                requested_by = session['email']
                otp_request = web_user_otp(otp=otp, request_id=request_id, requested_by=requested_by, otp_used=False, otp_expired=False)
                db.session.add(otp_request)
                db.session.commit()
                sendemail(requested_by, "Your OTP for login", str(otp))
                # Redirect to home page
                flash('Moving to OTP auth')
                return redirect(url_for('otp_verify'))
            else:
                print("Email not found or not active")
                msg = 'Email not found or not active'

        else:
            # Account doesnt exist or username/password incorrect
            print("Invalid email")
            msg = 'Invalid email'
    # Show the login form with message (if any)
    return render_template('index.html', msg=msg)


@app.route('/otp', methods=['GET', 'POST'])
def otp_verify():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'otp_input' in request.form:
        print("Inside OTP Form")
        # Create variables for easy access
        otp_web = request.form['otp_input']
        if 'cancel' in request.form:
            return redirect(url_for('login'))
        if 'verify' in request.form:
            print("Verify clicked")
        print(otp_web)
        # Check if account exists using MySQL
        #email = username+"@votesapp.co.in"

        otp = web_user_otp.query.filter(web_user_otp.otp == otp_web ).first()
        print(otp)
        if otp:
            if otp.otp_used==True:
                return 'OTP is not active'
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            # Redirect to home page
            return redirect(url_for('home'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Invalid OTP'
    # Show the login form with message (if any)
    return render_template('otp_verify.html', msg=msg)
# http://localhost:5000/python/logout - this will be the logout page
@app.route('/admin/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    print("Inside register")
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    #if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
    if request.method == 'POST':
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        print(username,password,role)
        email = username + "@votesapp.co.in"
        account = web_user.query.filter(web_user.email == email).first()
         # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not role:
            msg = 'Please fill out the form and submit!'
        else:
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            register_user = web_user(email=email,password=password,role=role,active=False)
            db.session.add(register_user)
            db.session.commit()
            msg = 'You have successfully registered!'
    #elif request.method == 'POST':
        # Form is empty... (no POST data)
        #msg = 'Please fill out the form and submit!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)


# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for loggedin users
@app.route('/branactivities')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        brands = new_brand_requests.query.filter(new_brand_requests.decision != 'approved', new_brand_requests.active == False)

        return render_template('Brand_approval_activities.html', brands=brands, username=session['email'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/branactivities-view', methods=['GET', 'POST'])
def expand_brand():
    selected_row = request.args.get('row_id')
    brand_id = request.args.get('brand_id')
    brandname = request.args.get('brandname')
    branddescription = request.args.get('branddescription')
    brandcategory = request.args.get('brandcategory')
    brandtype = request.args.get('brandtype')
    posted_by_user = request.args.get('posted_by_user')
    brandemail = request.args.get('brandemail')
    brandweb = request.args.get('brandweb')
    print(brandname)
    if request.method == 'POST' and 'decision' in request.form:
        decision = request.form['decision']
        if 'reject' in request.form:
            #return redirect(url_for('login'))
            print("Reject clicked")
            rbrand = new_brand_requests.query.filter_by(brand_id=brand_id).first()

            #if not rbrand:
                #return jsonify({'message': 'No pulse found to update!'}), 204

            rbrand.active = False
            rbrand.decision = "rejected"
            rbrand.decision_reason = decision
            rbrand.status_change_dt = datetime.datetime.utcnow()
            rbrand.modified_by = session['email']
            db.session.commit()
            return redirect(url_for('home'))

        if 'approve' in request.form:
            print("Approve clicked")
            rbrand = new_brand_requests.query.filter_by(brand_id=brand_id).first()

            # if not rbrand:
            # return jsonify({'message': 'No pulse found to update!'}), 204
            rbrand.active = True
            rbrand.decision = "approved"
            rbrand.decision_reason = decision
            rbrand.status_change_dt = datetime.datetime.utcnow()
            rbrand.modified_by = session['email']
            db.session.commit()
            return redirect(url_for('home'))
        print(decision)

    return render_template('expand_brand.html', selected_row=selected_row, brand_id=brand_id, brandname=brandname, branddescription=branddescription, brandcategory=brandcategory, brandtype=brandtype, posted_by_user=posted_by_user, brandemail=brandemail, brandweb=brandweb)
# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for loggedin users
@app.route('/admin/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        account = web_user.query.filter(web_user.email == session['username']).first()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


if __name__ == '__main__':
    session_id=-1
    session_email = ''
    app.run(debug=True)