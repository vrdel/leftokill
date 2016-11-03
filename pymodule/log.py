import logging
import logging.handlers
import sys

logname = 'leftokilld'
logfile = '/var/log/leftokill/leftokill.log'

class Logger(object):
    logger = None

    def _init_stdout(self):
        lfs = '%(name)s: %(levelname)s %(message)s'
        lf = logging.Formatter(lfs)
        lv = logging.INFO

        logging.basicConfig(format=lfs, level=lv, stream=sys.stdout)
        self.logger = logging.getLogger(logname)

    def init_syslog(self):
        lfs = '%(name)s[%(process)s]: %(levelname)s %(message)s'
        lf = logging.Formatter(lfs)
        lv = logging.INFO

        sh = logging.handlers.SysLogHandler('/dev/log', logging.handlers.SysLogHandler.LOG_USER)
        sh.setFormatter(lf)
        sh.setLevel(lv)
        self.logger.addHandler(sh)

    def init_filelog(self):
        lfs = '%(asctime)s %(name)s[%(process)s]: %(levelname)s %(message)s'
        lf = logging.Formatter(fmt=lfs, datefmt='%Y-%m-%d %H:%M:%S')
        lv = logging.INFO

        sf = logging.handlers.RotatingFileHandler(logfile, maxBytes=1024*1024, backupCount=5)
        sf.setFormatter(lf)
        sf.setLevel(lv)
        self.logger.addHandler(sf)

    def __init__(self):
        self._init_stdout()

    def get(self):
        return self.logger
