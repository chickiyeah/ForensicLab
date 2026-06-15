from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

db = SQLAlchemy()
migrate = Migrate()

# flask/ 프로젝트 루트 (이 파일은 flask/monitor/__init__.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")

    cfg = os.environ.get("APP_CONFIG_FILE",
                         os.path.join(BASE_DIR, "config", "production.py"))
    app.config.from_pyfile(cfg)

    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)

    from monitor.views.main import bp as main_bp
    from monitor.views.tools import bp as tools_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(tools_bp)

    return app
