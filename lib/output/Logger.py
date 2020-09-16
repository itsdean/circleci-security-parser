import logging

class Logger:

    def __init__(self, name):
        logging.basicConfig(level=logging.DEBUG)
        self.l = logging.getLogger(name)

    def error(self, m):
        self.l.error(m)

    def debug(self, m):
        self.l.debug(m)