from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

db = SQLAlchemy()
migrate = Migrate()


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    cfg = os.environ.get('APP_CONFIG_FILE', '/app/config/production.py')
    app.config.from_pyfile(cfg)

    os.makedirs('/app/data', exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)

    from monitor.views.main import bp as main_bp
    from monitor.views.tools import bp as tools_bp
    from monitor.views.monitor import bp as monitor_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(tools_bp)
    app.register_blueprint(monitor_bp)

    return app
