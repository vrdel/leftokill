#!/usr/bin/python

import psutil
import pwd
import time
import daemon
import datetime
import logging
import logging.handlers
import sys

homeprefix = '/home/'
logname = 'leftokill'

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

def daemon_func(logger):
    while True:
        pt = psutil.process_iter()
        candidate_list = list()
        report_info = dict()

        for p in pt:
            if p.ppid() == 1:
                homedir = pwd.getpwnam(p.username())[5]
                if homedir.startswith(homeprefix):
                    candidate_list.append(p)
                    report_info.update({p.pid: {'name': p.name(), 'username': p.username(),
                                                'created': datetime.datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                                                'status': p.status(), 'cpuuser': p.cpu_times()[0], 'cpusys': p.cpu_times()[1],
                                                'rss': bytes2human(p.memory_info()[0]), 'cmdline': ' '.join(p.cmdline())}})
                    curdict = report_info[p.pid]
                    logger.info('PID:(%d) Candidate:(%s) User:(%s) Created:(%s) Status:(%s) CPU:(user=%s, sys=%s) Memory:(RSS=%s) CMD:(%s)' \
                                % (p.pid, curdict['name'], curdict['username'], curdict['created'],
                                   curdict['status'], curdict['cpuuser'], curdict['cpusys'],
                                   curdict['rss'], curdict['cmdline']))

        if candidate_list:
            for p in candidate_list:
                p.terminate()
            gone, alive = psutil.wait_procs(candidate_list, timeout=10)
            if gone:
                for p in gone:
                    logger.info('SIGTERM - PID:(%d) Candidate:(%s) User:(%s) Returncode:(%s)' \
                                % (p.pid, report_info[p.pid]['name'], report_info[p.pid]['username'], p.returncode))
            for p in alive:
                p.kill()
                logger.info('SIGKILL - PID:(%d) Candidate:(%s) User:(%s) Returncode:(%s)' \
                            % (p.pid, report_info[p.pid]['name'], report_info[p.pid]['username'], p.returncode))

        time.sleep(15)

def main():
    logger = init_syslog()

    context_daemon = daemon.DaemonContext()
    with context_daemon:
        daemon_func(logger)
    # daemon_func(logger)

main()
