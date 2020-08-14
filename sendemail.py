import smtplib
server = smtplib.SMTP_SSL('smtp.zoho.in', 465)
server.login('service@votesapp.co.in','UzpiR7aHw9Y1')
server.sendmail('service@votesapp.co.in','admin@votesapp.co.in', " ".join('Hello there'))
server.quit()