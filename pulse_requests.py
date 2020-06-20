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

class new_pulse_requests(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(45))
    type_name = db.Column(db.String(300))
    type_name_native = db.Column(db.String(300))
    type_short_name = db.Column(db.String(45))
    urlstring = db.Column(db.String(45))
    active = db.Column(db.Boolean)
    active_changed_dt = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    brand_id = db.Column(db.Integer)
    category = db.Column(db.String(100))
    claimed = db.Column(db.Boolean)
    country = db.Column(db.String(100))
    geo = db.Column(db.String(100))
    last_reset_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    last_updated_date = db.Column(db.DateTime)
    official_email = db.Column(db.String(150))
    official_website = db.Column(db.String(300))
    posted_by_dt = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    posted_by_user = db.Column(db.String(300))
    pulse_id = db.Column(db.Integer)
    state = db.Column(db.String(100))
    tag = db.Column(db.String(45))

# static list of categories and types(sub categories)
class pulse_category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50))
    type = db.Column(db.String(45))
    status = db.Column(db.Boolean)



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
#get the list of categories and sub categories(type) when a user click on post pulse/brand in the app
@app.route('/static/category', methods=['GET'])
@token_required
def get_category(current_user):
    if not current_user.active:
        return jsonify({'message': 'Cannot perform that function!'})

    categories = pulse_category.query.filter(pulse_category.status == True)

    if categories.count() == 0:
        return jsonify({'message': 'Category not found!'}), 204


    output = []
    for cat in categories:
        data = {}
        #data['categories'] = {"id": cat.id, "category":cat.category, "type":cat.type}
        data['id'] = cat.id
        data['category'] = cat.category
        data['type'] = cat.type
        output.append(data)

    return jsonify({'results': output})

@app.route('/requests/edit', methods=['POST'])
@token_required
def edit_requests(current_user):
    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    edit_request = edit_pulse_requests(category=data['category'], field_edited=data['field_edited'], old_value=data['old_value'],new_value=data['new_value'],approved=data['approved'],pid=data['pid'], requested_date=datetime.datetime.utcnow())
    db.session.add(edit_request)
    db.session.commit()

    return jsonify({'message' : 'New pulse edit request created!'})

@app.route('/requests/create', methods=['POST'])
@token_required
def create_requests(current_user):
    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    create_request = new_pulse_requests(type=data['type'],type_name=data['type_name'],type_name_native=data['type_name_native'],active_changed_dt=datetime.datetime.utcnow(),brand_id=data['brand_id'],category=data['category'],claimed=data['claimed'],country=data['country'],geo=data['geo'],last_reset_date=datetime.datetime.utcnow(),last_updated_date=datetime.datetime.utcnow(),official_email=data['official_email'],official_website=data['official_website'],posted_by_dt=datetime.datetime.utcnow(),posted_by_user=data['posted_by_user'],pulse_id=data['pulse_id'],state=data['state'],tag=data['tag'])
    db.session.add(create_request)
    db.session.commit()

    return jsonify({'message' : 'New pulse request created!'})


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