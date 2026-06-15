from flask import Blueprint, render_template, request, jsonify
from monitor.models import Sensor
from monitor import db

bp = Blueprint('monitor', __name__, url_prefix='/monitor')


@bp.route('/sensor')
def sensor():
    sensors = Sensor.query.order_by(Sensor.regdate.desc()).limit(100).all()
    return render_template('monitor/sensor.html', sensors=sensors)


@bp.route('/sensor/data', methods=['POST'])
def sensor_data():
    part = request.form.get('part', '').strip()
    data = request.form.get('data', 0)
    if not part:
        return jsonify(error='part required'), 400
    s = Sensor(part=part, data=data)
    db.session.add(s)
    db.session.commit()
    return jsonify(ok=True)


@bp.route('/sensor/api')
def sensor_api():
    sensors = Sensor.query.order_by(Sensor.regdate.desc()).limit(50).all()
    return jsonify([{
        'part': s.part,
        'data': float(s.data or 0),
        'regdate': s.regdate.strftime('%Y-%m-%d %H:%M:%S'),
    } for s in sensors])
