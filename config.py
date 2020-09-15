import os

S3_BUCKET = os.environ.get("S3_BUCKET")
S3_KEY = os.environ.get("S3_KEY")
S3_SECRET = os.environ.get("S3_SECRET_ACCESS_KEY")

SECRET_KEY = os.environ.get("SECRET_KEY")
SQL_Host   = os.environ.get("SQL_Host")
SQL_User = os.environ.get("SQL_User")
SQL_Password = os.environ.get("SQL_Password")
DB = os.environ.get("DB")

URI = 'mysql://' + SQL_User +':'+ SQL_Password +'@' + SQL_Host + '/' + DB