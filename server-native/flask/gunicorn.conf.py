# 네이티브 배포: nginx 가 앞단(reverse proxy)이라 localhost 로만 바인드
bind = '127.0.0.1:5000'
workers = 1
worker_class = 'gthread'
threads = 8
# 운영 서버이므로 자동 reload 비활성화 (개발 시 True 로)
reload = False
reload_extra_files = ['monitor/templates', 'monitor/static/css/my.css']
