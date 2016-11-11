#!/usr/bin/python

import datetime
import psutil
import pwd
import re
import signal
import socket
import sys
import threading
import time

from leftokill import reportmail

homeprefix = '/home/'
reported, report_leftovers = set(), dict()


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


def find_candidates(excusers, excprocess):
    pt = psutil.process_iter()
    candidate_list = set()

    for p in pt:
        if p.ppid() == 1:
            homedir = pwd.getpwnam(p.username())[5]
            if p.username() not in excusers:
                if homedir.startswith(homeprefix):
                    def fil(e):
                        if re.search(e, ' '.join(p.cmdline())):
                            return True
                    if filter(fil, excprocess):
                        continue
                    candidate_list.add(p)

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
            rmsg = 'SIGTERM - PID:%d Returncode:%s' % (p.pid, p.returncode)
            report_leftovers[p.pid]['msg']['main'].append(rmsg)

        for p in palive:
            rmsg = 'SIGKILL - PID:%d' % (p.pid )
            report_leftovers[p.pid]['msg']['main'].append(rmsg)

        for c in cgone:
            rmsg = 'SIGTERM CHILD - PID:%d Returncode:%s' % (c.pid, c.returncode)
            report_leftovers[p.pid]['msg']['childs'].append(rmsg)

        for c in calive:
            rmsg = 'SIGKILL CHILD - PID:%d' % (c.pid)
            report_leftovers[p.pid]['msg']['childs'].append(rmsg)


def build_report_syslog(leftovers, confopts):
    global reported
    report_syslog, torepkeys, msg = dict(), list(), list()

    if reported:
        torepkeys = set(leftovers.keys()) - reported
    else:
        torepkeys = set(leftovers.keys())
    for tr in torepkeys:
        report_syslog.update({tr: leftovers[tr]})

    if report_syslog and confopts['noexec']:
        msg.append('NoExecute mode')

    for e in report_syslog.itervalues():
        msg.append(e['msg']['candidate'])
        for l in e['msg']['main']:
            msg.append(l)
        for l in e['msg']['childs']:
            msg.append(l)

    reported.update(leftovers.keys())

    return msg


def run(confopts, logger, events):
    global report_leftovers
    lock = threading.Lock()
    termev = threading.Event()

    if confopts['sendreport']:
        events.update({'flushonterm': threading.Event()})
        rth = reportmail.Report(logger, lock, events, report_leftovers,
                                reported, confopts)
        rth.start()

    logger.info('Started: Report=%s NoExec=%s' % (confopts['sendreport'], confopts['noexec']))

    while True:
        lock.acquire(False)

        candidate_list = find_candidates(confopts['excludeusers'],
                                         confopts['excludeprocesses'])

        if candidate_list:
            for cand in candidate_list:
                build_report_leftovers(cand=cand)

                if confopts['noexec'] == False:
                    cgone, calive, pgone, palive = term_and_kill(cand)
                    build_report_leftovers(pgone=pgone, palive=palive, cgone=cgone,
                                       calive=calive)

            for m in build_report_syslog(report_leftovers, confopts):
                logger.info(m)

        if confopts['sendreport'] == False:
            report_leftovers.clear()
            reported.clear()

        lock.release()

        if events['term'].isSet():
            if confopts['sendreport']:
                events['flushonterm'].set()
                rth.join()
            logger.info('Exit')
            events['term'].clear()
            raise SystemExit(0)

        time.sleep(confopts['killeverysec'])
