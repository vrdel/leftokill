from email.mime.text import MIMEText
import datetime
import smtplib
import socket
import threading
import time
import logging

class Report(threading.Thread):
    def _report_payload(self, report_entry):
        execmode = ''
        if self.confopt['noexec']:
            execmode = '[NoExecute mode] - '

        report_string = 'Report (every %.1fh) - %s' % (self.confopt['reporteveryhour']/3600, \
                                                       (execmode) + str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + '\n')
        for e in report_entry.itervalues():
            report_string += '\n' + e['msg']['candidate'] + '\n'
            for l in e['msg']['main']:
                report_string += l + '\n'
            for l in e['msg']['childs']:
                report_string += l + '\n'
        return report_string

    def _report_email(self, report_email):
        msg = MIMEText(self._report_payload(report_email))
        msg['From'] = self.confopt['reportfrom']
        msg['To'] = self.confopt['reportto']
        node = '- ' + self.confopt['reportnode'] if self.confopt['reportnode'] else ''
        if self.confopt['noexec']:
            num = len(report_email)
            prstr = 'process' if num == 1 else 'processes'
            msg['Subject'] = 'leftokill(NoExec) %s: %d %s to clean' % (node, len(report_email), prstr)
        else:
            num = len(report_email)
            prstr = 'process' if num == 1 else 'processes'
            msg['Subject'] = 'leftokill %s: %d %s cleaned' % (node, len(report_email), prstr)

        return msg.as_string()

    def _send_email(self):
        try:
            port = 25 if not self.confopt['reportsmtpssl'] else 587
            s = smtplib.SMTP(self.confopt['reportsmtp'], port, timeout=120)
            if self.confopt['reportsmtpssl']:
                s.starttls()
            s.ehlo()
            if self.confopt['reportsmtplogin'] and self.confopt['reportsmtppass']:
                s.login(self.confopt['reportsmtplogin'], self.confopt['reportsmtppass'])
            s.sendmail(self.confopt['reportfrom'], [self.confopt['reportto']], self._report_email(self.leftovers))
            s.quit()
        except (socket.error, smtplib.SMTPException) as e:
            self.logger.error(repr(self.__class__.__name__).replace('\'', '') + ': ' + repr(e))
            return False

        return True

    def run(self):
        s = 0.0
        while True:
            if s == round(self.confopt['reporteveryhour'], 0):
                if self.leftovers:
                    self.lock.acquire()

                    if self._send_email():
                        self.logger.info('Sent report with %d leftovers' % (len(self.leftovers)))

                        if self.confopt['noexec'] == False:
                            self.leftovers.clear()
                            self.reported.clear()

                        self.lock.release()
                s = 0.0

            if self.events['flushonterm'].isSet():
                if self.leftovers:
                    if self._send_email():
                        self.logger.info('Flushed report with %d leftovers' % (len(self.leftovers)))
                        self.lock.release()
                self.events['flushonterm'].clear()
                break

            time.sleep(1.0)
            s += 1.0

    def __init__(self, logger, lock, events, leftovers, reported, confopt):
        self.logger = logger
        self.lock = lock
        self.events = events
        self.leftovers = leftovers
        self.reported = reported
        self.confopt = confopt
        threading.Thread.__init__(self)
        self.daemon = True
