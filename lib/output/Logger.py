import logging

STREAM_FORMAT = "%(asctime)s %(levelname)s %(name)s - %(message)s"

class Logger:


    def __init__(self, verbose=False):

        logging.basicConfig(
            level = logging.INFO,
            format = STREAM_FORMAT,
            datefmt = "%H:%M:%S"
        )

        self.l = logging.getLogger(__name__)

        if verbose:
            self.l.setLevel(logging.DEBUG)


    def critical(self, m):
        self.l.critical(m)


    def error(self, m):
        self.l.error(m)


    def warning(self, m):
        self.l.warning(m)


    def info(self, m):
        self.l.info(m)


    def debug(self, m):
        self.l.debug(m)