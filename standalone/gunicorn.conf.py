bind = '0.0.0.0:5000'
workers = 1
worker_class = 'gthread'
threads = 8
reload = True
reload_extra_files = ['monitor/templates', 'monitor/static/css/my.css']
