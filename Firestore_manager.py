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
'''
#Add neew field in all documents
abuse_ref = fire_db.collection(u'questions').get()
for doc in abuse_ref:
    print(f'{doc.id} => {doc.to_dict()}')
    update_ref = fire_db.collection(u'questions').document(doc.id)
    #update_ref.update({u'active_change_dt': firestore.SERVER_TIMESTAMP})
    update_ref.update({u'abuse_verified': False})
    update_ref.update({u'active_change_madeby': ""})
    update_ref.update({u'inactive_reason': ""})
    '''

from google.cloud import storage
from google.cloud.storage import Blob
import datetime

storage_client = storage.Client.from_service_account_json(firebase_key)

# get all the buckets
buckets = storage_client.list_buckets()
for bucket in buckets:
    print(bucket.name)
# output  bucket_name

# get all the blobs in a bucket
bucket = storage_client.get_bucket("testvotes-d4cd7.appspot.com")
fname="questions/Technology/rjnfxs3crPdFJrwr3mcDYuC8lku1-8081299.jpg"
stats = storage.Blob(bucket=bucket, name=fname).exists(storage_client)
print("File exists?",stats)
blob = bucket.blob(fname)
signed_url=blob.generate_signed_url(datetime.timedelta(seconds=300), method='GET')
print(signed_url)
#blobs = list(bucket.list_blobs())
#for blob in blobs:
    #print (blob)
    #print(blob.generate_signed_url(datetime.timedelta(seconds=300), method='GET'))
# print the blobs: blob_name

#check if the blob exists
#assert isinstance(bucket.get_blob('blob_name'), Blob)

#get the blob from path
my_blob = Blob.from_string("gs://testvotes-d4cd7.appspot.com/blob_name")

# List the files in a folder
files = bucket.list_blobs(prefix='folder_name')
#for f in files:
    #print(f.name)
