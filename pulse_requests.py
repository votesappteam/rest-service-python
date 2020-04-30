from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt  #we have to install pyJWT
import datetime
from functools import wraps
#import pymysql
from flask_pymongo import PyMongo
import pymongo
import re
import configparser
import pprint


app = Flask(__name__)


#Read the config file
configFile = '/var/www/votesapp-rest/config.ini'

config = configparser.ConfigParser()
config.read(configFile)


#PySQL configurations

userpass = config['MYSQLDB']['USERPASS']
basedir  = '127.0.0.1'
dbname   = '/votesapp_db'
socket = config['MYSQLDB']['SOCKET']
dbname   = dbname + socket


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

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    uid = db.Column(db.String(50))
    password = db.Column(db.String(80))
    active = db.Column(db.Boolean)

class edit_pulse_requests(db.Model):
    request_id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(15))
    field_edited = db.Column(db.String(45))
    old_value = db.Column(db.String(300))
    new_value = db.Column(db.String(300))
    approved_by = db.Column(db.String(50))
    approved = db.Column(db.Boolean)
    requested_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    approved_date = db.Column(db.DateTime)
    pid = db.Column(db.String(100))


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated
@app.route('/requests/check/<check_pid>', methods=['GET'])
@token_required
def check_requestr(current_user,check_pid):
    if not current_user.active:
        return jsonify({'message': 'Cannot perform that function!'})

    results = edit_pulse_requests.query.filter(edit_pulse_requests.approved == False, edit_pulse_requests.pid == check_pid)

    if results.count() == 0:
        return jsonify({'message': 'No pulse edit found!'}), 204

    output = []
    for qr in results:
        data = {}
        data['field_edited'] = qr.field_edited
        output.append(data)

    return jsonify({'results': output})

@app.route('/requests/edit', methods=['POST'])
@token_required
def edit_requestr(current_user):
    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    edit_request = edit_pulse_requests(category=data['category'], field_edited=data['field_edited'], old_value=data['old_value'],new_value=data['new_value'],approved=data['approved'],pid=data['pid'], requested_date=datetime.datetime.utcnow())
    db.session.add(edit_request)
    db.session.commit()

    return jsonify({'message' : 'New pulse edit request created!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(uid=auth.username).first()

    if not user:
        return make_response('Could not verify: user not found', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=1)}, app.config['SECRET_KEY']) #Token expiry mentioned here

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify: Invalid user password', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run(debug=True)