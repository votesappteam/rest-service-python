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
#import json
import re
import configparser
import pprint
#import classify
#Reference Video
# https://www.youtube.com/watch?v=WxGBoY5iNXY

app = Flask(__name__)


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

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    uid = db.Column(db.String(50))
    password = db.Column(db.String(80))
    active = db.Column(db.Boolean)


class Questions(db.Model):

    __tablename__ = 'questions'
    __searchable__ = ['question']
    id = db.Column(db.Integer, primary_key=True)
    qid = db.Column(db.String(200))
    question = db.Column(db.String(300))
    posted_dt = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    category = db.Column(db.String(15))
    posted_by = db.Column(db.Integer)
    active = db.Column(db.Boolean)
    photo_URL = db.Column(db.String(200))
    urlstring = db.Column(db.String(50))
    tagstring = db.Column(db.String(25))

class Pulse(db.Model):
    __tablename__ = 'pulse'
    __searchable__ = ['pulse_type', 'pulse_type_name', 'pulse_type_name_native', 'pulse_type_name_short']
    id = db.Column(db.Integer, primary_key=True)
    pid = db.Column(db.String(200))
    pulse_type = db.Column(db.String(300))
    pulse_type_name = db.Column(db.String(300))
    pulse_type_name_native = db.Column(db.String(300))
    pulse_type_name_short = db.Column(db.String(300))
    posted_dt = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    category = db.Column(db.String(15))
    posted_by = db.Column(db.Integer)
    active = db.Column(db.Boolean)
    photo_URL = db.Column(db.String(200))
    urlstring = db.Column(db.String(50))
    tagstring = db.Column(db.String(25))

class Locations(db.Model):

    __tablename__ = 'locations'
    __searchable__ = ['c2','c0','c4','c5','c6']
    id = db.Column(db.Integer, primary_key=True)
    c2 = db.Column(db.Text())
    c0 = db.Column(db.String(40))
    c4 = db.Column(db.String(60))
    c5 = db.Column(db.String(60))
    c6 = db.Column(db.String(60))

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



@app.route('/api/questions/get/<question_txt>', methods=['GET'])
@token_required
def get_question(current_user, question_txt):

    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})

    search_str = "%{}%".format(question_txt)
    #question_results = Questions.query.filter(Questions.question.like(search_str)).order_by(Questions.posted_dt.desc()).all()
    #Filter and search questions. The query returns only the question is active
    question_results = Questions.query.filter(Questions.active == True,
        or_(Questions.question.like(search_str), Questions.tagstring.like(search_str))).order_by(
        Questions.posted_dt.desc()).all()

    if not question_results:
        return jsonify({'message' : 'No question found!'}), 204

    output = []

    for qr in question_results:
        data = {}
        data['qid'] = qr.qid
        data['question'] = qr.question
        data['posted_dt'] = qr.posted_dt
        data['category'] = qr.category
        data['posted_by'] = qr.posted_by
        data['photo_URL'] = qr.photo_URL
        data['urlstring'] = qr.urlstring
        data['tagstring'] = qr.tagstring
        output.append(data)

    return jsonify({'questions': output})

@app.route('/api/questions/post', methods=['POST'])
@token_required
def create_question(current_user):
    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    #hashed_password = generate_password_hash(data['password'], method='sha256')

    new_question = Questions(qid=data['qid'], question=data['question'], posted_dt=datetime.datetime.utcnow(), category=data['category'],posted_by=data['posted_by'],photo_URL=data['photo_URL'],active=data['active'],urlstring=data['urlstring'],tagstring=data['tagstring'])
    db.session.add(new_question)
    db.session.commit()

    return jsonify({'message' : 'New question created!'})

@app.route('/api/questions/update', methods=['PUT'])
@token_required
def promote_user(current_user):
    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})
    data = request.get_json()
    question_id = data['qid']
    action = data['action']
    question = Questions.query.filter_by(qid=question_id).first()

    if not question:
        return jsonify({'message' : 'No question found to update!'}), 204

    question.active = action
    db.session.commit()

    return jsonify({'message' : 'The question has been updated!'})

@app.route('/api/questions/update/<question_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, question_id):
    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})

    question = Questions.query.filter_by(qid=question_id).first()

    if not question:
        return jsonify({'message' : 'No question found to delete!'}), 204

    db.session.delete(question)
    db.session.commit()

    return jsonify({'message' : 'The question has been deleted!'})

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


############# PULSE Requests ##########################


@app.route('/api/pulse/get/<pulse_text>', methods=['GET'])
@token_required
def search_pulse(current_user, pulse_text):
    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})

    search_str = "%{}%".format(pulse_text)

    pulse_results = Pulse.query.filter(or_(Pulse.pulse_type_name.like(search_str), Pulse.pulse_type_name_native.like(search_str) , Pulse.pulse_type_name_short.like(search_str))).order_by(
        Pulse.posted_dt.desc())

    if pulse_results.count() == 0:
        return jsonify({'message': 'No pulse found!'}), 204


    output = []

    for pr in pulse_results:
        pulse_data = {}
        pulse_data['pid'] = pr.pid
        pulse_data['pulse_type'] = pr.pulse_type
        pulse_data['pulse_type_name'] = pr.pulse_type_name
        pulse_data['pulse_type_name_native'] = pr.pulse_type_name_native
        pulse_data['pulse_type_name_short'] = pr.pulse_type_name_short
        pulse_data['posted_dt'] = pr.posted_dt
        pulse_data['category'] = pr.category
        pulse_data['posted_by'] = pr.posted_by
        pulse_data['active'] = pr.active
        pulse_data['photo_URL'] = pr.photo_URL
        pulse_data['urlstring'] = pr.urlstring
        pulse_data['tagstring'] = pr.tagstring
        output.append(pulse_data)

    return jsonify({'Pulse': output})

@app.route('/api/pulse/post', methods=['POST'])
@token_required
def create_pulse(current_user):
    if not current_user.active:
        return jsonify({'message': 'Cannot perform that function!'})

    data = request.get_json()

    # hashed_password = generate_password_hash(data['password'], method='sha256')

    new_pulse = Pulse(pid=data['pid'], pulse_type=data['pulse_type'], pulse_type_name=data['pulse_type_name'],
                         pulse_type_name_native=data['pulse_type_name_native'],
                         pulse_type_name_short=data['pulse_type_name_short'], posted_dt=datetime.datetime.utcnow(),
                         category=data['category'], posted_by=data['posted_by'], photo_URL=data['photo_URL'],
                         active=data['active'],urlstring=data['urlstring'],tagstring=data['tagstring'])
    db.session.add(new_pulse)
    db.session.commit()

    return jsonify({'message': 'New pulse created!'})

@app.route('/api/pulse/update', methods=['PUT'])
@token_required
def update_pulse(current_user):
    if not current_user.active:
        return jsonify({'message': 'Cannot perform that function!'})
    data = request.get_json()
    pulse_id = data['pid']
    action = data['action']
    pulse = Pulse.query.filter_by(pid=pulse_id).first()

    if not pulse:
        return jsonify({'message': 'No pulse found to update!'}), 204

    pulse.active = action
    db.session.commit()

    return jsonify({'message': 'The pulse has been updated!'})

@app.route('/api/pulse/delete/<pulse_id>', methods=['DELETE'])
@token_required
def delete_pulse(current_user, pulse_id):
    if not current_user.active:
        return jsonify({'message': 'Cannot perform that function!'})

    pulse = Pulse.query.filter_by(pid=pulse_id).first()

    if not pulse:
        return jsonify({'message': 'No pulse found to delete!'}), 204

    db.session.delete(pulse)
    db.session.commit()

    return jsonify({'message': 'The pulse has been deleted!'})

#Locations search for posting questions
@app.route('/api/locations/get/<search_txt>', methods=['GET'])
@token_required
def get_locations(current_user, search_txt):

    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})

    search_str = "%{}%".format(search_txt)
    location_results = Locations.query.filter(or_(Locations.c0.like(search_str),Locations.c2.contains(search_str),Locations.c4.like(search_str),Locations.c5.like(search_str),Locations.c6.like(search_str))).order_by(Locations.c0)

    if location_results.count() == 0:
        return jsonify({'message': 'No locations found!'}), 204

    output = []
    getlocation = set()  # Set is remove the duplicate locations
    search_txt = search_txt.lower()
    for lr in location_results:

        if search_txt in lr.c0.lower():
            getlocation.add(lr.c0)

    # If users search the zipcode, display until the subdistrict
        if search_txt in lr.c2.lower():
            #getlocation.add(lr.c0+"→"+lr.c4+"→"+lr.c5+"→"+lr.c6)
            getlocation.add(lr.c6+"→"+lr.c5+"→"+lr.c4+"→"+lr.c0)
        if search_txt in lr.c4.lower():
            #getlocation.add(lr.c0+"→"+lr.c4)
            getlocation.add(lr.c4+"→"+lr.c0)
        if search_txt in lr.c5.lower():
            #getlocation.add(lr.c0+"→"+lr.c4+"→"+lr.c5)
            getlocation.add(lr.c5+"→"+lr.c4+"→"+lr.c0)
        if search_txt in lr.c6.lower():
            #getlocation.add(lr.c0+"→"+lr.c4+"→"+lr.c5+"→"+lr.c6)
            getlocation.add(lr.c6+"→"+lr.c5+"→"+lr.c4+"→"+lr.c0)
    for item in getlocation:
        data = {}
        data['locstr'] = item
        output.append(data)
    return jsonify({'locations': output})


#Locations search for changing locations in the settings-->Profile
@app.route('/api/locations/get/profile/<search_txt>', methods=['GET'])
@token_required
def get_profile_locations(current_user, search_txt):

    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})

    search_str = "%{}%".format(search_txt)
    location_results = Locations.query.filter(or_(Locations.c0.like(search_str),Locations.c2.contains(search_str),Locations.c4.like(search_str),Locations.c5.like(search_str),Locations.c6.like(search_str))).order_by(Locations.c0)

    if not location_results:
        return jsonify({'message' : 'No locations found!'}), 204

    output = []

    for lr in location_results:
        data = {}
        data['locstr'] = lr.c0+"|"+lr.c4+"|"+lr.c5+"|"+lr.c6+"::"+lr.c2
        output.append(data)

    return jsonify({'locations': output})

#Locations search for changing locations in the settings-->Profile
@app.route('/api/locations/get/profile/gps/<search_txt>', methods=['GET'])
@token_required
def get_gps_locations(current_user, search_txt):

    if not current_user.active:
        return jsonify({'message' : 'Cannot perform that function!'})
    splitStr = search_txt.split('|')
    zipStr = splitStr[0]
    countryStr = splitStr[1]
    search_str = "%{}%".format(zipStr)
    location_results = Locations.query.filter(Locations.c0 == countryStr,Locations.c2.contains(search_str)).first()

    if not location_results:
        return jsonify({'message' : 'No locations found!'}), 204

    output = []


    data = {}
    data['country'] = location_results.c0
    data['state'] = location_results.c4
    data['district'] = location_results.c5
    data['subdistrict'] = location_results.c6
    output.append(data)

    return jsonify({'locations': output})

#Locations search with mongo
@app.route('/api/locations-mongo/get/<search_txt>', methods=['GET'])
@token_required
def get_locations_mongo(current_user, search_txt):

    if not current_user.active:
        return jsonify({'message': 'Cannot perform that function!'})
    regx = re.compile("/^"+search_txt+"/", re.IGNORECASE)
    search_str = "/.*{}*/".format(search_txt)
    locations_data = mongo.db.locations
    #location = locations_data.find({"c2": regx})
    location = locations_data.find({"$text": { "$search": search_str}})
    #db.stores.find({ $text: { $search: "java coffee shop"}} )

    if not location:
        return jsonify({'message': 'No locations found!'}), 204
    output = []
    for loc in location:
        data = {}
        data['locstr'] = loc['c0']+"|"+loc['c4']+"|"+loc['c5']+"|"+loc['c6']+"::"+loc['c2']
        output.append(data)

    return jsonify({'locations':output})


#Question Insights - Locations based insights - Mongodb collection creation
@app.route('/api/createinsight-mongo', methods=['POST'])
@token_required
def createinsightmongo(current_user):
    '''{
        "qid" : "TN-KL-L2",
        "qlocation" : ["Tamil Nadu→India","Kerala→India"],
        "ansarray" : ["a","b","c","d","e"]
     }'''
    if not current_user.active:
        return jsonify({'message': 'Cannot perform that function!'})

    data = request.get_json()
    qid = data['qid']
    qlocations = data['qlocation']
    ansarray = data['ansarray']
    anscol = {}
    for ans in ansarray:
        anscol[ans] = int(0)
    #print(anscol)

    col = {}
    col['_id'] = qid
    #print(qlocations)
    iteration = 0
    state = {}
    district = {}
    previous_country = ""
    loc_count = len(qlocations)
    for loc in qlocations:
        iteration = iteration + 1
        loc_array = loc.split("→")
        loc_array.reverse()
        subdistrict = {}

        if loc_array[0] not in col:
            col[loc_array[0]] = {"cnt": anscol }

        if len(loc_array) == 2:
            if loc_array[1] not in state and loc_array[0] != previous_country:
                state = {}
            state[loc_array[1]] = {"cnt": anscol}
            state["cnt"] = anscol
            previous_country = loc_array[0]
            col[loc_array[0]] = state

            district = {}

            results = Locations.query.filter(Locations.c4 == loc_array[1]).all()
            districts = []
            for r in results:
                districts.append(r.c5)
            districts = list(set(districts))
            for dt in districts:
                district[dt] = anscol
                district["cnt"] = anscol
                col[loc_array[0]][loc_array[1]] = district
                subdistrict = {}
                for item in results:
                    if item.c5 == dt:
                        subdistrict[item.c6] = {"cnt" : anscol }
                        subdistrict["cnt"] = anscol
                col[loc_array[0]][loc_array[1]][dt] = subdistrict


        elif len(loc_array) == 3:
            if loc_array[1] not in state:
                state = {}
                state[loc_array[1]] = {"cnt": anscol}
                state["cnt"] = anscol
                col[loc_array[0]][loc_array[1]] = {"cnt": anscol}

            if loc_array[2] not in district:
                district = {}
                district[loc_array[2]] = {"cnt": anscol}
                district["cnt"] = anscol
                col[loc_array[0]][loc_array[1]][loc_array[2]] = district

            results = Locations.query.filter(Locations.c5 == loc_array[2]).all()
            subdistrict = {}
            innercnt = {}
            for r in results:
                subdistrict[r.c6] = {"cnt" :anscol }
                subdistrict["cnt"] = anscol
                col[loc_array[0]][loc_array[1]][loc_array[2]] = subdistrict


        elif len(loc_array) == 4:

            if loc_array[1] not in state:
                state = {}
                state[loc_array[1]] = {"cnt":anscol}
                state["cnt"] = anscol
                col[loc_array[0]][loc_array[1]] = {"cnt":anscol}


            if loc_array[2] not in district:
                district = {}
                district[loc_array[2]] = {"cnt": anscol}
                district["cnt"] = anscol
                col[loc_array[0]][loc_array[1]] = district

            if loc_array[3] not in subdistrict:
                subdistrict = {}
                subdistrict[loc_array[3]] = {"cnt": anscol}
                subdistrict["cnt"] = anscol

            col[loc_array[0]][loc_array[1]][loc_array[2]][loc_array[3]] = {"cnt": anscol}


        else:
            state = {}
            results = Locations.query.filter(Locations.c0 == loc_array[0]).all()
            states = []
            for r in results:
                states.append(r.c4)
            states = list(set(states))

            for st in states:
                state[st] = anscol
                state["cnt"] = anscol
                col[loc_array[0]] = state
                district = {}
                for item in results:
                    if item.c4 == st:

                        district[item.c5] = {"cnt" : anscol }
                        district["cnt"] = anscol

                col[loc_array[0]][st] = district

    #print(col)
    #pprint.pprint(col)
    conn = pymongo.MongoClient(mongo_connect_str)
    mongodb = conn[mongo_db]
    mongocol = mongodb[qid]
    mongocol.insert(col)

    return jsonify({'locations': 'Collection created successfully'})


#Question Insights - Locations based insights - Mongodb collection creation
@app.route('/api/updateinsight-mongo', methods=['POST'])
@token_required
def updateinsightmongo(current_user):
    #Rest post input
    '''{
         "qid" : "India",
         "userloc" : "Perundurai→Erode→Tamil Nadu→India",
         "country" : "India",
         "state": "Tamil Nadu",
         "district": "Erode",
         "subdistrict": "Perundurai",
         "geodepth" : {"India":2},
         "answer" : "a"
       }'''
    if not current_user.active:
        return jsonify({'message': 'Cannot perform that function!'})

    data = request.get_json()
    country = data['country']
    state = data['state']
    district = data['district']
    subdistrict = data['subdistrict']
    aid = data['answer']
    geodepth = data['geodepth']
    qid = data['qid']

    conn = pymongo.MongoClient(mongo_connect_str)
    mongodb = conn[mongo_db]
    mongocol = mongodb[qid]
    mongocol.update({'_id': str(qid)}, {'$inc': {country + '.' + 'cnt' + '.' + aid: int(1)}})
    mongocol.update({'_id': str(qid)}, {'$inc': {country + '.' + state + '.' + 'cnt' + '.' + aid: int(1)}})
    mongocol.update({'_id': str(qid)}, {'$inc': {country + '.' + state + '.' + district + '.' + 'cnt' + '.' + aid: int(1)}})
    if geodepth[country] > 1:
        mongocol.update({'_id': str(qid)},{'$inc': {country + '.' + state + '.' + district + '.' + subdistrict + '.' + 'cnt' + '.' + aid: int(1)}})

    return jsonify({'Insights': 'Collection updated successfully'})


#NSFW - POST Method
@app.route('/api/nsfw', methods=['POST'])
@token_required
#Ref : https://www.roytuts.com/python-flask-rest-api-file-upload/
def upload_file(current_user):
    if not current_user.active:
        return jsonify({'message': 'Cannot perform that function!'})
# check if the post request has the file part
    if 'file' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        fullpath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        resp = jsonify({'message': "Upload sucess"})
        #resp = jsonify({'message': classify.detect(fullpath)})
        resp.status_code = 201

        return resp
    else:
        resp = jsonify({'message' : 'Allowed file types are  png, jpg, jpeg, gif'})
        resp.status_code = 400
        return resp

if __name__ == '__main__':
    app.run(debug=True)
