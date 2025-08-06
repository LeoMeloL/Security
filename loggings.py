import logging
from logging.handlers import RotatingFileHandler
from flask import request

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] IP:%(remote_addr)s - %(message)s'
)
class RequestFormatter(logging.Formatter):
    def format(self, record):
        record.remote_addr = getattr(record, 'remote_addr', 'N/A')
        return super().format(record)
request_formatter = RequestFormatter(
    '%(asctime)s [%(levelname)s] IP:%(remote_addr)s - %(message)s'
)
handler.setFormatter(request_formatter)


def init_logging(app):
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    @app.before_request
    def log_req():
        app.logger.info(
            f"{request.method} {request.path} data={request.get_data(as_text=True)}",
            extra={'remote_addr': request.remote_addr}
        )
