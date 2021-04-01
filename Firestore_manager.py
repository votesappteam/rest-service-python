#This code used to alter the firestore collections and documents
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

# Read the config file
configFile = '/var/www/votesapp-rest/config.ini'
firebase_key = '/var/www/votesapp-rest/testvotes-d4cd7-firebase-adminsdk-oqlux-66b40b5463.json'

# Use a service account
cred = credentials.Certificate(firebase_key)
firebase_admin.initialize_app(cred)
fire_db = firestore.client()
# https://firebase.google.com/docs/firestore/quickstart#python

abuse_ref = fire_db.collection(u'questions').get()
for doc in abuse_ref:
    print(f'{doc.id} => {doc.to_dict()}')
    update_ref = fire_db.collection(u'questions').document(doc.id)
    #update_ref.update({u'active_change_dt': firestore.SERVER_TIMESTAMP})
    update_ref.update({u'abuse_verified': False})
    update_ref.update({u'active_change_madeby': ""})
    update_ref.update({u'inactive_reason': ""})