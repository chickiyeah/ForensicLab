# 이미 떠 있는 nginx 가 5000 으로 프록시 → gunicorn 은 5000 에서 대기
bind = '0.0.0.0:5000'
workers = 1
worker_class = 'gthread'
threads = 8
# 운영 서버이므로 자동 reload 비활성화 (개발 시 True 로)
reload = False
reload_extra_files = ['monitor/templates', 'monitor/static/css/my.css']
