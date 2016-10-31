#!/usr/bin/python

import ConfigParser
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
reported, report_email = set(), dict()

class Report(threading.Thread):
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
            s.sendmail(confopt['reportfrom'], [confopt['reportto']], self._report_email(report_email))
            s.quit()
        except (socket.error, smtplib.SMTPException) as e:
            logger.error(repr(self.__class__.__name__).replace('\'', '') + ': ' + repr(e))

    def run(self):
        global report_email

        while True:
            if report_email:
                lock.acquire()

                self._send_email()

                if confopt['noexec'] == False:
                    report_email = {}

                lock.release()

            time.sleep(confopt['reporteveryhour'])

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

def init_syslog():
    lfs = '%(name)s[%(process)s]: %(levelname)s %(message)s'
    lf = logging.Formatter(lfs)
    lv = logging.INFO

    logging.basicConfig(format=lfs, level=lv, stream=sys.stdout)
    logger = logging.getLogger(logname)
    sh = logging.handlers.SysLogHandler('/dev/log', logging.handlers.SysLogHandler.LOG_USER)
    sh.setFormatter(lf)
    sh.setLevel(lv)
    logger.addHandler(sh)

    return logger

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

def build_report_email(cand=None, pgone=list(), palive=list(), cgone=list(), calive=list()):
    global report_email

    if cand:
        proc_childs = cand.children(recursive=True)
        report_email[cand.pid] = dict({'name': cand.name(), 'username': cand.username(), 'nchilds': len(proc_childs),
                                    'created': datetime.datetime.fromtimestamp(cand.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                                    'status': cand.status(), 'cpuuser': cand.cpu_times()[0], 'cpusys': cand.cpu_times()[1],
                                    'rss': bytes2human(cand.memory_info()[0]), 'cmdline': ' '.join(cand.cmdline())})

        report_email[cand.pid]['msg'] = dict({'candidate': 'PID:(%d) Candidate:(%s) User:(%s) Created:(%s) Status:(%s) Childs:(%d) CPU:(user=%s, sys=%s) Memory:(RSS=%s) CMD:(%s)' \
                    % (cand.pid, report_email[cand.pid]['name'], report_email[cand.pid]['username'], report_email[cand.pid]['created'],
                        report_email[cand.pid]['status'], report_email[cand.pid]['nchilds'], report_email[cand.pid]['cpuuser'],
                        report_email[cand.pid]['cpusys'], report_email[cand.pid]['rss'], report_email[cand.pid]['cmdline'])})
        report_email[cand.pid]['msg'].update(dict({'main': list()}))
        report_email[cand.pid]['msg'].update(dict({'childs': list()}))

    else:
        for p in pgone:
            rmsg = 'SIGTERM - PID:(%d) Candidate:(%s) User:(%s) Returncode:(%s)' \
                        % (p.pid, report_email[p.pid]['name'], report_email[p.pid]['username'], p.returncode)
            report_email[p.pid]['msg']['main'].append(rmsg)

        for p in palive:
            rmsg = 'SIGKILL - PID:(%d) Candidate:(%s) User:(%s)' \
                        % (p.pid, report_email[p.pid]['name'], report_email[p.pid]['username'])
            report_email[p.pid]['msg']['main'].append(rmsg)

        for c in cgone:
            rmsg = 'SIGTERM CHILD - PID:(%d) Candidate:(%s) User:(%s) Returncode:(%s)' \
                        % (c.pid, report_email[p.pid]['name'], report_email[p.pid]['username'], c.returncode)
            report_email[p.pid]['msg']['childs'].append(rmsg)

        for c in calive:
            rmsg = 'SIGKILL CHILD - PID:(%d) Candidate:(%s) User:(%s)' \
                        % (c.pid, report_email[p.pid]['name'], report_email[p.pid]['username'])
            report_email[p.pid]['msg']['childs'].append(rmsg)

def build_report_syslog(report_email):
    global reported
    report_syslog, torepkeys, msg = dict(), list(), list()

    if reported:
        torepkeys = set(report_email.keys()) - reported
    else:
        torepkeys = set(report_email.keys())
    for tr in torepkeys:
        report_syslog.update({tr: report_email[tr]})

    for e in report_syslog.itervalues():
        if confopt['verbose']:
            msg.append(e['msg']['candidate'])
        for l in e['msg']['main']:
            msg.append(l)
        for l in e['msg']['childs']:
            msg.append(l)

    reported.update(report_email.keys())

    return msg

def daemon_func():
    global report_email

    if confopt['sendreport'] == True:
        rth = Report()
        rth.daemon = True
        rth.start()

    while True:
        lock.acquire(False)

        candidate_list = build_candidates()

        if candidate_list:
            for cand in candidate_list:
                build_report_email(cand=cand)

                if confopt['noexec'] == False:
                    cgone, calive, pgone, palive = term_and_kill(cand)
                    build_report_email(pgone=pgone, palive=palive, cgone=cgone,
                                       calive=calive)

            for m in build_report_syslog(report_email):
                logger.info(m)

        if confopt['sendreport'] == False:
            report_email = {}

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
    logger = init_syslog()
    parse_config(conffile)

    context_daemon = daemon.DaemonContext()
    with context_daemon:
       daemon_func()
    # daemon_func()

main()
