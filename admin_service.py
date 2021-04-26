import configparser
import datetime
import math
import random
# import json
import re
import string

import flask
from flask import Flask, render_template, request, redirect, url_for, session, flash
# import pymysql
from flask_pymongo import PyMongo
from flask_sqlalchemy import SQLAlchemy
from source.mail_service import sendemail

app = Flask(__name__)

# Firebase related
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore


# Read the config file
configFile = '/var/www/votesapp-rest/config.ini'
firebase_key = '/var/www/votesapp-rest/testvotes-d4cd7-firebase-adminsdk-oqlux-66b40b5463.json'

config = configparser.ConfigParser()
config.read(configFile)

# PySQL configurations

userpass = config['MYSQLDB']['USERPASS']
basedir = '127.0.0.1'
dbname = '/votesapp_db'
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
mongo_db = 'votesapp_db'
# Mongo configuration
app.config['MONGO_DBNAME'] = 'votesapp_db'
app.config['MONGO_URI'] = mongo_connect_str + mongo_db
mongo = PyMongo(app)

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
session = {}
session['valid_email'] = False
session['abuseListToHTML'] =[]


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Use a service account
cred = credentials.Certificate(firebase_key)
firebase_admin.initialize_app(cred)
fire_db = firestore.client()
# https://firebase.google.com/docs/firestore/quickstart#python

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


# Reference --> https://codeshack.io/login-system-python-flask-mysql/
@app.route('/', methods=['GET', 'POST'])
def login():
    ip_address = flask.request.remote_addr
    print(ip_address)
    error = None
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'email' in request.form:
        # Create variables for easy access
        email = request.form['email']
        print(email)
        # Check if account exists using MySQL
        # email = username+"@votesapp.co.in"

        if email:
            active = web_user.query.filter(web_user.email == email).first()

            if active:
                if active.active == False:
                    return 'Account is not active'
                # Create session data, we can access this data in other routes

                session['id'] = active.id
                session['email'] = active.email
                session['valid_email'] = True
                otp = int(generate_otp())
                request_id = generate_request_id()
                requested_by = session['email']
                otp_request = web_user_otp(otp=otp, request_id=request_id, requested_by=requested_by, otp_used=False,
                                           otp_expired=False)
                db.session.add(otp_request)
                db.session.commit()
                sendemail(requested_by, "Your OTP for login", str(otp))
                # Redirect to home page
                flash('Moving to OTP auth')
                return redirect(url_for('otp_verify'))
            else:
                session['valid_email'] = False
                print("Email not found or not active")
                msg = 'Email not found or not active'

        else:
            # Account doesnt exist or username/password incorrect
            session['valid_email'] = False
            print("Invalid email")
            msg = 'Invalid email'
    # Show the login form with message (if any)
    return render_template('index.html', msg=msg)


@app.route('/otp', methods=['GET', 'POST'])
def otp_verify():

    # To check whether an email validated
    print(session['valid_email'])
    if session['valid_email'] == False:
        print("Email not validated")
        return redirect(url_for('login'))
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
        # email = username+"@votesapp.co.in"

        otp = web_user_otp.query.filter(web_user_otp.otp == otp_web).first()
        print(otp)
        if otp:
            if otp.otp_used == True or otp.otp_expired == True:
                msg = 'OTP is expired'
                return render_template('otp_verify.html', msg=msg)
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            otp.otp_used = True
            otp.otp_expired = True
            db.session.commit()
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
    session.clear()
    #response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
    session['valid_email'] = False
    session['loggedin'] = False
    session.pop('loggedin', None)
    session['abuseListToHTML'] = []
    session.pop('id', None)
    session.pop('email', None)
    # Redirect to login page
    return  redirect(url_for('login'))


# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    print("Inside register")
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    # if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
    if request.method == 'POST':
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        print(username, password, role)
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
            register_user = web_user(email=email, password=password, role=role, active=False)
            db.session.add(register_user)
            db.session.commit()
            msg = 'You have successfully registered!'
    # elif request.method == 'POST':
    # Form is empty... (no POST data)
    # msg = 'Please fill out the form and submit!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)


# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for loggedin users
@app.route('/branactivities')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        brands = new_brand_requests.query.filter(new_brand_requests.decision != 'approved',
                                                 new_brand_requests.active == False)

        return render_template('Brand_approval_activities.html', brands=brands, username=session['email'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/abuseactivities')
def abuse():
    # Check if user is loggedin
    if 'loggedin' in session:
        #At first time we fetch top 10 abuse records, for every back and forth, we should not go to firebase and fetch again and again.. So we action on all items in the list then on ly go to firebase
        if len(session['abuseListToHTML']) > 0 :
            return render_template('Abuse_questions_activities.html', questions=session['abuseListToHTML'], username=session['email'])
        from google.cloud import storage
        from google.cloud.storage import Blob
        import datetime

        storage_client = storage.Client.from_service_account_json(firebase_key)
        bucket = storage_client.get_bucket("testvotes-d4cd7.appspot.com")
        # User is loggedin show them the home page
        abuse_ref = fire_db.collection(u'questions')
        #query = abuse_ref.where(u'active', u'==', True)
        query = abuse_ref.limit(10).where(u'active', u'==', True).where(u'reportabuse', u'>', 1).where(u'abuse_verified', u'==', False).order_by(u'reportabuse', direction=firestore.Query.DESCENDING).order_by(u'upvote').stream()
            #results = query.stream()


        for q in query:
            qdict = q.to_dict()
            qdict["qid"] = q.id #add the document id along with other data
            #print(qdict['reportabuse'])
            fname="questions/" + qdict['category']+"/" + q.id + ".jpg"
            stats = storage.Blob(bucket=bucket, name=fname).exists(storage_client)
            if stats:
                blob = bucket.blob(fname)
                image_signed_url = blob.generate_signed_url(datetime.timedelta(seconds=300), method='GET')
            else:
                image_signed_url="static/img/temp-image/no-image.jpeg"
            qdict["image_signed_url"] = image_signed_url
            print(image_signed_url)
            session['abuseListToHTML'].append(qdict.copy())


        return render_template('Abuse_questions_activities.html', questions=session['abuseListToHTML'], username=session['email'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/branactivities-view', methods=['GET', 'POST'])
def expand_brand():
    if 'loggedin' in session:
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
            brand_ref = fire_db.collection(u'brands').document(brand_id)
            if 'reject' in request.form:
                # return redirect(url_for('login'))
                print("Reject clicked")

                update_data = {
                    u'active': False,
                    u'status_change_dt': firestore.SERVER_TIMESTAMP,
                    u'decision': "rejected",
                    u'decision_reason': decision
                }
                brand_ref.update(update_data)

                rbrand = new_brand_requests.query.filter_by(brand_id=brand_id).first()

                # if not rbrand:
                # return jsonify({'message': 'No pulse found to update!'}), 204

                rbrand.active = False
                rbrand.decision = "rejected"
                rbrand.decision_reason = decision
                rbrand.status_change_dt = datetime.datetime.utcnow()
                rbrand.modified_by = session['email']
                db.session.commit()

                return redirect(url_for('home'))

            if 'approve' in request.form:
                print("Approve clicked")

                update_data = {
                    u'active': True,
                    u'status_change_dt': firestore.SERVER_TIMESTAMP,
                    u'decision': "approved",
                    u'decision_reason': decision
                }
                brand_ref.update(update_data)
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

    return render_template('expand_brand.html', selected_row=selected_row, brand_id=brand_id, brandname=brandname,
                           branddescription=branddescription, brandcategory=brandcategory, brandtype=brandtype,
                           posted_by_user=posted_by_user, brandemail=brandemail, brandweb=brandweb)



@app.route('/abuseactivities-view', methods=['GET', 'POST'])
def expand_abuse():
    if 'loggedin' in session:
        qid = request.args.get('qid')
        user_id = request.args.get('user_id')
        question = request.args.get('question')
        category = request.args.get('category')
        totalvote = request.args.get('totalvote')
        upvote = request.args.get('upvote')
        reportabuse = request.args.get('reportabuse')
        status = request.args.get('active')
        question_type = request.args.get('question_type')
        image_signed_url = request.args.get('image_signed_url')

        if request.method == 'POST' and 'decision' in request.form:
            decision = request.form['decision']
            #Remove the item which is actioned from the screen
            session['abuseListToHTML'] = [item for item in session['abuseListToHTML'] if item['qid'] == qid]
            abuse_ref = fire_db.collection(u'questions').document(qid)
            if 'reject' in request.form:
                # return redirect(url_for('login'))
                print("Inactive clicked")

                update_data = {
                    u'active': False,
                    u'active_change_dt': firestore.SERVER_TIMESTAMP,
                    u'abuse_verified':True,
                    u'active_change_madeby': session['email'],
                    u'inactive_reason': decision
                }
                abuse_ref.update(update_data)

                return redirect(url_for('home'))

            if 'reject-user' in request.form:
                # return redirect(url_for('login'))
                print("Inactive user clicked")
                #Disable the question
                update_data = {
                    u'active': False,
                    u'active_change_dt': firestore.SERVER_TIMESTAMP,
                    u'abuse_verified': True,
                    u'active_change_madeby': session['email'],
                    u'inactive_reason': decision
                }
                abuse_ref.update(update_data)
                #Stop the user to post the question
                user_ref = fire_db.collection(u'users').document(user_id)
                update_user_data = {
                    u'canCreatePolls': False
                }
                user_ref.update(update_user_data)
                return redirect(url_for('home'))

            if 'approve' in request.form:
                print("Approve clicked")

                update_data = {
                    u'active': True,
                    u'active_change_dt': firestore.SERVER_TIMESTAMP,
                    u'abuse_verified': True,
                    u'active_change_madeby': session['email'],
                    u'inactive_reason': decision
                }
                abuse_ref.update(update_data)
                #return redirect(url_for('home'))
                return render_template('Abuse_questions_activities.html', questions=session['abuseListToHTML'], username=session['email'])
            print(decision)

    return render_template('expand_abuse.html',   qid = qid,  user_id = user_id,question = question,category = category, totalvote = totalvote,upvote = upvote,reportabuse = reportabuse,status = status, question_type = question_type, image_signed_url=image_signed_url)


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
    debug = bool(config['DEBUG']['DEBUG'])
    session_id = -1
    session_email = ''
    app.run(debug=debug)

