#!/usr/bin/python

import ConfigParser
import argparse
import daemon
import datetime
import json
import logging
import logging.handlers
import psutil
import pwd
import socket
import sys
import threading
import time

import smtplib
from email.mime.text import MIMEText

homeprefix = '/home/'
logname = 'leftokill'
# conffile = 'leftokill.conf'
conffile = '/etc/leftokill/leftokill.conf'
confopt = dict()
logger = None
lock = threading.Lock()
reported, report_leftovers = set(), dict()
logfile = '/var/log/leftokill/leftokill.log'

class Logger(object):
    logger = None

    def _init_stdout(self):
        lfs = '%(name)s[%(process)s]: %(levelname)s %(message)s'
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

class ReportEmail(threading.Thread):
    def _report_payload(self, report_entry):
        execmode = ''
        if confopt['noexec']:
            execmode = 'NoExecute mode - '

        report_string = 'Report - %s' % (execmode) + str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + '\n'
        for e in report_entry.itervalues():
            if confopt['verbose']:
                report_string += '\n' + e['msg']['candidate'] + '\n'
            for l in e['msg']['main']:
                report_string += l + '\n'
            for l in e['msg']['childs']:
                report_string += l + '\n'
        return report_string

    def _report_email(self, report_email):
        msg = MIMEText(self._report_payload(report_email))
        msg['From'] = confopt['reportfrom']
        msg['To'] = confopt['reportto']
        msg['Subject'] = 'Leftokill'

        return msg.as_string()

    def _send_email(self):
        try:
            s = smtplib.SMTP(confopt['reportsmtp'], 587)
            s.starttls()
            s.ehlo()
            s.login(confopt['reportsmtplogin'], confopt['reportsmtppass'])
            s.sendmail(confopt['reportfrom'], [confopt['reportto']], self._report_email(report_leftovers))
            s.quit()
        except (socket.error, smtplib.SMTPException) as e:
            logger.error(repr(self.__class__.__name__).replace('\'', '') + ': ' + repr(e))
            return False

        return True

    def run(self):
        global report_leftovers

        while True:
            if report_leftovers:
                lock.acquire()

                if self._send_email():
                    logger.info('Sent report with %d killed leftovers' % (len(report_leftovers)))

                    if confopt['noexec'] == False:
                        report_leftovers = {}

                    lock.release()

            time.sleep(confopt['reporteveryhour'])

def term_and_kill(candidate):
    cgone, calive, pgone, palive = list(), list(), list(), list()
    childs = dict()

    proc_childs = candidate.children(recursive=True)

    if len(proc_childs) > 0:
        childs[candidate.pid] = proc_childs

        if childs.get(candidate.pid):
            for c in childs[candidate.pid]:
                c.terminate()

            cgone, calive = psutil.wait_procs(childs[candidate.pid], timeout=3)

            for c in calive:
                c.kill()

    candidate.terminate()

    pgone, palive = psutil.wait_procs([candidate], timeout=3)

    for p in palive:
        p.kill()

    return cgone, calive, pgone, palive

def build_candidates():
    pt = psutil.process_iter()
    candidate_list = list()

    for p in pt:
        if p.ppid() == 1:
            homedir = pwd.getpwnam(p.username())[5]

            if homedir.startswith(homeprefix):
                candidate_list.append(p)

    return candidate_list

def build_report_leftovers(cand=None, pgone=list(), palive=list(), cgone=list(), calive=list()):
    global report_leftovers

    def bytes2human(n):
        symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
        prefix = {}

        for i, s in enumerate(symbols):
            prefix[s] = 1 << (i + 1) * 10

        for s in reversed(symbols):
            if n >= prefix[s]:
                value = float(n) / prefix[s]
                return '%.1f%s' % (value, s)

        return "%sB" % n

    if cand:
        proc_childs = cand.children(recursive=True)
        report_leftovers[cand.pid] = dict({'name': cand.name(), 'username': cand.username(), 'nchilds': len(proc_childs),
                                    'created': datetime.datetime.fromtimestamp(cand.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                                    'status': cand.status(), 'cpuuser': cand.cpu_times()[0], 'cpusys': cand.cpu_times()[1],
                                    'rss': bytes2human(cand.memory_info()[0]), 'cmdline': ' '.join(cand.cmdline())})

        report_leftovers[cand.pid]['msg'] = dict({'candidate': 'PID:%d Candidate:%s User:%s Created:%s Status:%s Childs:%d CPU:user=%s, sys=%s Memory:RSS=%s CMD:%s' \
                    % (cand.pid, report_leftovers[cand.pid]['name'], report_leftovers[cand.pid]['username'], report_leftovers[cand.pid]['created'],
                        report_leftovers[cand.pid]['status'], report_leftovers[cand.pid]['nchilds'], report_leftovers[cand.pid]['cpuuser'],
                        report_leftovers[cand.pid]['cpusys'], report_leftovers[cand.pid]['rss'], report_leftovers[cand.pid]['cmdline'])})
        report_leftovers[cand.pid]['msg'].update(dict({'main': list()}))
        report_leftovers[cand.pid]['msg'].update(dict({'childs': list()}))

    else:
        for p in pgone:
            rmsg = 'SIGTERM - PID:%d Candidate:%s User:%s Returncode:%s' \
                        % (p.pid, report_leftovers[p.pid]['name'], report_leftovers[p.pid]['username'], p.returncode)
            report_leftovers[p.pid]['msg']['main'].append(rmsg)

        for p in palive:
            rmsg = 'SIGKILL - PID:%d Candidate:%s User:%s' \
                        % (p.pid, report_leftovers[p.pid]['name'], report_leftovers[p.pid]['username'])
            report_leftovers[p.pid]['msg']['main'].append(rmsg)

        for c in cgone:
            rmsg = 'SIGTERM CHILD - PID:%d Candidate:%s User:%s Returncode:%s' \
                        % (c.pid, report_leftovers[p.pid]['name'], report_leftovers[p.pid]['username'], c.returncode)
            report_leftovers[p.pid]['msg']['childs'].append(rmsg)

        for c in calive:
            rmsg = 'SIGKILL CHILD - PID:%d Candidate:%s User:%s' \
                        % (c.pid, report_leftovers[p.pid]['name'], report_leftovers[p.pid]['username'])
            report_leftovers[p.pid]['msg']['childs'].append(rmsg)

def build_report_syslog(leftovers):
    global reported
    report_syslog, torepkeys, msg = dict(), list(), list()

    if reported:
        torepkeys = set(leftovers.keys()) - reported
    else:
        torepkeys = set(leftovers.keys())
    for tr in torepkeys:
        report_syslog.update({tr: leftovers[tr]})

    for e in report_syslog.itervalues():
        if confopt['verbose']:
            msg.append(e['msg']['candidate'])
        for l in e['msg']['main']:
            msg.append(l)
        for l in e['msg']['childs']:
            msg.append(l)

    reported.update(leftovers.keys())

    return msg

def daemon_func():
    global report_leftovers

    if confopt['sendreport'] == True:
        rth = ReportEmail()
        rth.daemon = True
        rth.start()

    while True:
        lock.acquire(False)

        candidate_list = build_candidates()

        if candidate_list:
            for cand in candidate_list:
                build_report_leftovers(cand=cand)

                if confopt['noexec'] == False:
                    cgone, calive, pgone, palive = term_and_kill(cand)
                    build_report_leftovers(pgone=pgone, palive=palive, cgone=cgone,
                                       calive=calive)

            for m in build_report_syslog(report_leftovers):
                logger.info(m)

        if confopt['sendreport'] == False:
            report_leftovers = {}

        lock.release()

        time.sleep(confopt['killeverysec'])

def parse_config(conffile):
    global confopt

    try:
        config = ConfigParser.ConfigParser()
        if config.read(conffile):
            for section in config.sections():
                if section.startswith('General'):
                    if config.has_option(section, 'KillEverySec'):
                        confopt['killeverysec'] = float(config.get(section, 'KillEverySec'))
                    if config.has_option(section, 'NoExecute'):
                        confopt['noexec'] = eval(config.get(section, 'NoExecute'))
                    if config.has_option(section, 'LogMode'):
                        val = config.get(section, 'LogMode')
                        if ',' in val:
                            confopt['logmode'] = map(lambda v: v.strip(), val.split(','))
                        else:
                            confopt['logmode'] = [val.strip()]
                if section.startswith('Report'):
                    if config.has_option(section, 'Send'):
                        confopt['sendreport'] = eval(config.get(section, 'Send'))
                    if config.has_option(section, 'To'):
                        confopt['reportto'] = config.get(section, 'To')
                    if config.has_option(section, 'From'):
                        confopt['reportfrom'] = config.get(section, 'From')
                    if config.has_option(section, 'SMTP'):
                        confopt['reportsmtp'] = config.get(section, 'SMTP')
                    if config.has_option(section, 'SMTPLogin'):
                        confopt['reportsmtplogin'] = config.get(section, 'SMTPLogin')
                    if config.has_option(section, 'SMTPPass'):
                        confopt['reportsmtppass'] = config.get(section, 'SMTPPass')
                    if config.has_option(section, 'EveryHours'):
                        confopt['reporteveryhour'] = 3600 * float(config.get(section, 'EveryHours'))
                    if config.has_option(section, 'Verbose'):
                        confopt['verbose'] = eval(config.get(section, 'Verbose'))
        else:
            logger.error('Missing %s' % config)
            raise SystemExit(1)

    except (ConfigParser.MissingSectionHeaderError, SystemExit) as e:
        if getattr(e, 'filename', False):
            logger.error(e.filename + ' is not a valid configuration file')
            logger.error(e.message)
        raise SystemExit(1)

def main():
    global logger
    lobj = Logger()
    logger = lobj.get()

    parse_config(conffile)

    for l in confopt['logmode']:
        if l.lower() == 'syslog':
            lobj.init_syslog()
        if l.lower() == 'file':
            lobj.init_filelog()

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', dest='nofork', action='store_true',
                        help="do not fork into background",
                        required=False)
    args = parser.parse_args()

    if args.nofork:
        try:
            daemon_func()
        except KeyboardInterrupt:
            raise SystemExit(1)
    else:
        context_daemon = daemon.DaemonContext()
        with context_daemon:
            daemon_func()

main()
