import datetime
import psutil
import pwd
import signal
import socket
import sys
import threading
import time

from leftokill import reportmail

homeprefix = '/home/'
reported, report_leftovers = set(), dict()


def term_and_kill(candidate, logger):
    cgone, calive, pgone, palive = list(), list(), list(), list()
    childs = dict()

    try:
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

    except psutil.NoSuchProcess as e:
        logger.warning(e)

    return cgone, calive, pgone, palive

def find_candidates(excusers, excprocess):
    pt = psutil.process_iter()
    candidate_list = set()

    for p in pt:
        if p.ppid() == 1:
            homedir = pwd.getpwnam(p.username())[5]
            if p.username() not in excusers:
                if homedir.startswith(homeprefix):
                    if excprocess and \
                            filter(lambda e: e in ' '.join(p.cmdline()), excprocess):
                        continue
                    candidate_list.add(p)

    return candidate_list

def build_report_leftovers(cand=None, pgone=list(), palive=list(), cgone=list(), calive=list()):
    global report_leftovers

    def extract_creattime(cand):
        return datetime.datetime.fromtimestamp(cand.create_time()).strftime("%Y-%m-%d %H:%M:%S")

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

    def build_report_entry(key, cand, msg=None):
        if not msg:
            report_leftovers[key] = dict({'name': cand.name(), 'username': cand.username(), 'nchilds': len(cand.children(recursive=True)),
                                        'created': datetime.datetime.fromtimestamp(cand.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                                        'status': cand.status(), 'cpuuser': cand.cpu_times()[0], 'cpusys': cand.cpu_times()[1],
                                        'rss': bytes2human(cand.memory_info()[0]), 'cmdline': ' '.join(cand.cmdline())})

            report_leftovers[key]['msg'] = dict({'candidate': 'PID:%d Candidate:%s User:%s Created:%s Status:%s Childs:%d CPU:user=%s, sys=%s Memory:RSS=%s CMD:%s' \
                        % (cand.pid, report_leftovers[key]['name'], report_leftovers[key]['username'], report_leftovers[key]['created'],
                            report_leftovers[key]['status'], report_leftovers[key]['nchilds'], report_leftovers[key]['cpuuser'],
                            report_leftovers[key]['cpusys'], report_leftovers[key]['rss'], report_leftovers[key]['cmdline'])})
            report_leftovers[key]['msg'].update(dict({'main': list()}))
            report_leftovers[key]['msg'].update(dict({'childs': list()}))

        else:
            report_leftovers[key] = dict()
            report_leftovers[key]['msg'] = dict({'candidate': msg})
            report_leftovers[key]['msg'].update(dict({'main': list()}))
            report_leftovers[key]['msg'].update(dict({'childs': list()}))

    if cand:
        key = extract_creattime(cand) + ' - ' + str(cand.pid)
        build_report_entry(key, cand)

    else:
        for p in pgone:
            key = extract_creattime(p) + ' - ' + str(p.pid)
            rmsg = 'SIGTERM - PID:%d Returncode:%s' % (p.pid, p.returncode)
            report_leftovers[key]['msg']['main'].append(rmsg)

        for p in palive:
            key = extract_creattime(p) + ' - ' + str(p.pid)
            rmsg = 'SIGKILL - PID:%d' % (p.pid)
            report_leftovers[key]['msg']['main'].append(rmsg)

        for c in cgone:
            try:
                key = extract_creattime(p) + ' - ' + str(p.pid)
                rmsg = 'SIGTERM CHILD - PID:%d Returncode:%s' % (c.pid, c.returncode)
                report_leftovers[key]['msg']['childs'].append(rmsg)
            except NameError:
                key = extract_creattime(c) + ' - ' + str(c.pid)
                build_report_entry(key, c, 0, 'Candidate (child exited): ' + str(c))

        for c in calive:
            try:
                key = extract_creattime(p) + ' - ' + str(p.pid)
                rmsg = 'SIGKILL CHILD - PID:%d' % (c.pid)
                report_leftovers[key]['msg']['childs'].append(rmsg)
            except NameError:
                key = extract_creattime(c) + ' - ' + str(c.pid)
                build_report_entry(key, c, 0, 'Candidate (child exited): ' + str(c))

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
                    cgone, calive, pgone, palive = term_and_kill(cand, logger)
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
