import smtplib

SMTPserver = smtplib.SMTP_SSL('smtp.zoho.in', 465)
sender =     'service@votesapp.co.in'
destination = ['versionanbu01@gmail.com']
USERNAME = 'service@votesapp.co.in'
PASSWORD = 'UzpiR7aHw9Y1'
#PASSWORD = 'Sindhu123$'

# typical values for text_subtype are plain, html, xml
text_subtype = 'plain'

content="""\
Test message
"""

subject="Sent from Python"

import sys
import os
import re

from smtplib import SMTP_SSL as SMTP       # this invokes the secure SMTP protocol (port 465, uses SSL)
# from smtplib import SMTP                  # use this for standard SMTP protocol   (port 25, no encryption)

# old version
# from email.MIMEText import MIMEText
from email.mime.text import MIMEText

try:
    msg = MIMEText(content, text_subtype)
    msg['Subject']=       subject
    msg['From']   = sender # some SMTP servers will do this automatically, not all
    msg['To'] = destination
    conn = smtplib.SMTP_SSL('smtp.zoho.in', 465)

    #conn.set_debuglevel(False)
    conn.login(USERNAME, PASSWORD)
    try:
        #conn.sendmail(sender, [destination], msg.as_string())
        conn.sendmail(sender, [destination], " ".join(msg))
    finally:
        conn.quit()

except:
    print(sys.exc_info()[0])
    raise
    sys.exit("mail failed; %s" % "CUSTOM_ERROR") # give an error message