Modifief from Digital Ocean Example https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login

1> Uses MySQL Database 

2> Uses Env parameters for  
    S3_BUCKET,
    S3_KEY,
    S3_SECRET,
    SECRET_KEY,
    SQL_Host,
    SQL_User,
    SQL_Password,
    DB,
    URI ### URI = 'mysql://' + SQL_User +':'+ SQL_Password +'@' + SQL_Host + '/' + Database

2B>  FLASK_RUN_PORT=8080

3> Modify base.template to add Upload Picture, and View Picture

4> Add images on AWS S3 ( aws-step2 exercise)
