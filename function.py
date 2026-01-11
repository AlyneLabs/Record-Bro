import bcrypt
import smtplib
import random
from pymongo import MongoClient
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def get_database(con, database):
    client = MongoClient(con)
    return client[database]

def hash_password(password):
    password_bytes = password.encode('utf-8')
    hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed_bytes.decode('utf-8')

def verify_password(provided_password, stored_hash):
    provided_password_bytes = provided_password.encode('utf-8')
    stored_hash_bytes = stored_hash.encode('utf-8')
    return bcrypt.checkpw(provided_password_bytes, stored_hash_bytes)

def register_user(db, username, email, password, otp_r, mail, passwd):
    user_records = db["user_records"]

    otp_s = send_verification_code(mail, passwd, email)

    if otp_s == otp_r:
        email_ver = True
    else:
        email_ver = False

    uniq = user_records.find({"username": username})

    if uniq == None:
        user_ver = True
    else:
        user_ver = False



    if email_ver and user_ver:
        data = {"username" : username,
                "email" : email,
                "password" : hash_password(password)}
        result = user_records.insert_one(data)
        return result.inserted_id
    
    elif not email_ver and not user_ver:
        return "1 | Email / Otp invalid. \n2 | Username aready exists. Choose a different one."""
    
    elif not email_ver:
        return "Email / Otp invalid."
    
    elif not user_ver:
        return "Username aready exists. Choose a different one."

def login_user(db, user, type, password):   
    user_records = db["user_records"]

    if type == "username":
        data = user_records.find({"username": user})
    elif type == "email":
        data = user_records.find({"email": user})
    else:
        return "Error in type of input."
    
    if data == None:
        return "No user Found."
    
    elif data != None:
        if verify_password(password, data["password"]):
            return "Login successfull."
        else:
            return "Login unsuccessfull."
    else:
        return "Error in data (not empty)."
    
def send_verification_code(mail, passwd, receiver_email):
    sender_email = mail
    app_password = passwd
    
    otp_code = str(random.randint(100000, 999999))
    
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Your Verification Code"
    
    body = "Hello! Your verification code for Record Bro platform is: "+otp_code+". It will expire in 10 minutes."
    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, app_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        
        print("Code sent : ",{receiver_email})
        return otp_code
    
    except Exception as e:
        print(f"Error: {e}")
        return "Error"
