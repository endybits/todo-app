import os

from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY='user_key',
        DATABASE_HOST=os.environ.get('FLASK_DATABASE_HOST'),
        DATABASE_USER=os.environ.get('FLASK_DATABASE_USER'),
        DATABASE_PASSWORD=os.environ.get('FLASK_DATABASE_PASSWORD'),
        DATABASE=os.environ.get('FLASK_DATABASE'),
    )
    #os.environ['FLASK_ENV'] = 'development'

    from .db import init_app
    init_app(app)

    @app.route('/hello')
    def hello():
        return {'hi': "Hi, this is a microservice created with Flask"}
    
    return app