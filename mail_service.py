import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import configparser
#Read the config file
configFile = '/var/www/votesapp-rest/config.ini'
config = configparser.ConfigParser()
config.read(configFile)

def sendemail(receipient,subject,body):
    mail_content = "Hi, Your OTP for the session is :" + body
    #The mail addresses and password
    sender_address = config['SECURITY']['EMAIL_SENDER']
    sender_pass = config['SECURITY']['EMAIL_PWD']
    receiver_address = receipient
    #Setup the MIME
    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = subject   #The subject line
    #The body and the attachments for the mail
    message.attach(MIMEText(mail_content, 'plain'))
    #Create SMTP session for sending the mail
    session = smtplib.SMTP('smtp.zoho.in', 587) #use zoho with port
    session.starttls() #enable security
    session.login(sender_address, sender_pass) #login with mail_id and password
    text = message.as_string()
    session.sendmail(sender_address, receiver_address, text)
    session.quit()
    print('Mail Sent')