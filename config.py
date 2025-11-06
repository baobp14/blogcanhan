#MAIL_USERNAME = 'legiabao14073@gmail.com'
#MAIL_PASSWORD = 'wgmj asnr vgix ttlx'

import os
basedir = os.path.abspath(os.path.dirname(__file__))

# Lấy thông tin MySQL từ file bạn cung cấp
DB_USERNAME = 'root'
DB_PASSWORD = '14072005'
DB_HOST = '127.0.0.1'
DB_NAME = 'flasky_db' 

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ban-nen-thay-doi-chuoi-nay-cho-an-toan'
    
    # CẤU HÌNH DATABASE MYSQL (Dùng mysql.connector)
    SQLALCHEMY_DATABASE_URI = f'mysql+mysqlconnector://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # CẤU HÌNH MAIL
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'legiabao14073@gmail.com'
    MAIL_PASSWORD = 'wgmj asnr vgix ttlx'
    FLASKY_MAIL_SUBJECT_PREFIX = '[Flasky]'
    
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        print("Cảnh báo: MAIL_USERNAME hoặc MAIL_PASSWORD chưa được set.")
        
    FLASKY_MAIL_SENDER = f'Flasky Admin <{os.environ.get("MAIL_USERNAME")}>'
    
    FLASKY_POSTS_PER_PAGE = 10