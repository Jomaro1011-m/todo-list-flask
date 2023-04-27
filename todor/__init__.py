from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template

db = SQLAlchemy()

def create_app():

    app = Flask(__name__)
    
    #Configuración del proyecto
    app.config.from_mapping(DEBUG = False, SECRET_KEY = 'devtod', 
    SQLALCHEMY_DATABASE_URI = 'sqlite:///todolist.db')
    
    db.init_app(app)
    
    #Registrar Bluprint
    from . import todo, auth
    app.register_blueprint(todo.bp)
    app.register_blueprint(auth.bp)

    @app.route('/')
    def index(): return render_template('index.html')
    
    with app.app_context(): db.create_all()
    
    return app