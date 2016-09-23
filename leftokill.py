#!/usr/bin/python

import psutil
import pwd
import time
import daemon
import datetime
import logging
import json
import logging.handlers
import sys
import ConfigParser
import threading

homeprefix = '/home/'
logname = 'leftokill'
conffile = '/etc/leftokill/leftokill.conf'
confopt = dict()
logger = None
lock = threading.Lock()
report_entry = dict()

class Report(threading.Thread):
    def run(self):
        global report_entry

        while True:
            if report_entry:
                lock.acquire()
                logger.info(json.dumps(report_entry, indent=4))

                report_entry = {}
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

def daemon_func():
    rth = Report()
    rth.daemon = True
    rth.start()
    global reportlines
    global report_entry

    while True:
        pt = psutil.process_iter()
        candidate_list = list()
        childs = dict()
        lock.acquire(False)

        for p in pt:
            if p.ppid() == 1:
                homedir = pwd.getpwnam(p.username())[5]

                if homedir.startswith(homeprefix):
                    candidate_list.append(p)
                    proc_childs = p.children(recursive=True)

                    if len(proc_childs) > 0:
                        childs[p.pid] = proc_childs

                    report_entry[p.pid] = dict({'name': p.name(), 'username': p.username(), 'nchilds': len(proc_childs),
                                               'created': datetime.datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                                               'status': p.status(), 'cpuuser': p.cpu_times()[0], 'cpusys': p.cpu_times()[1],
                                               'rss': bytes2human(p.memory_info()[0]), 'cmdline': ' '.join(p.cmdline())})

                    report_entry[p.pid]['msg'] = dict({'candidate': 'PID:(%d) Candidate:(%s) User:(%s) Created:(%s) Status:(%s) Childs:(%d) CPU:(user=%s, sys=%s) Memory:(RSS=%s) CMD:(%s)' \
                                % (p.pid, report_entry[p.pid]['name'], report_entry[p.pid]['username'], report_entry[p.pid]['created'],
                                   report_entry[p.pid]['status'], report_entry[p.pid]['nchilds'], report_entry[p.pid]['cpuuser'],
                                   report_entry[p.pid]['cpusys'], report_entry[p.pid]['rss'], report_entry[p.pid]['cmdline'])})
                    report_entry[p.pid]['msg'] = dict({'main': list()})
                    report_entry[p.pid]['msg'].update(dict({'childs': list()}))

        if candidate_list:
            for p in candidate_list:
                if childs.get(p.pid):
                    for c in childs[p.pid]:
                        c.terminate()

                    gone, alive = psutil.wait_procs(childs[p.pid], timeout=3)

                    for c in gone:
                        rmsg = 'SIGTERM CHILD - PID:(%d) Candidate:(%s) User:(%s) Returncode:(%s)' \
                                    % (c.pid, report_entry[p.pid]['name'], report_entry[p.pid]['username'], c.returncode)
                        report_entry[p.pid]['msg']['childs'].append(rmsg)

                    for c in alive:
                        c.kill()

                        rmsg = 'SIGKILL CHILD - PID:(%d) Candidate:(%s) User:(%s)' \
                                    % (c.pid, report_entry[p.pid]['name'], report_entry[p.pid]['username'])
                        report_entry[p.pid]['msg']['childs'].append(rmsg)

                p.terminate()

            gone, alive = psutil.wait_procs(candidate_list, timeout=3)

            for p in gone:
                rmsg = 'SIGTERM - PID:(%d) Candidate:(%s) User:(%s) Returncode:(%s)' \
                            % (p.pid, report_entry[p.pid]['name'], report_entry[p.pid]['username'], p.returncode)
                report_entry[p.pid]['msg']['main'].append(rmsg)

            for p in alive:
                p.kill()

                rmsg = 'SIGKILL - PID:(%d) Candidate:(%s) User:(%s)' \
                            % (p.pid, report_entry[p.pid]['name'], report_entry[p.pid]['username'])
                report_entry[p.pid]['msg']['main'].append(rmsg)

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
                        confopt['noexec'] = config.get(section, 'NoExecute')
                if section.startswith('Report'):
                    if config.has_option(section, 'Send'):
                        confopt['sendreport'] = config.get(section, 'Send')
                    if config.has_option(section, 'Email'):
                        confopt['reportemail'] = config.get(section, 'Email')
                    if config.has_option(section, 'EveryHours'):
                        confopt['reporteveryhour'] = float(config.get(section, 'EveryHours'))
                    if config.has_option(section, 'Verbose'):
                        confopt['verbose'] = bool(config.get(section, 'Verbose'))
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
