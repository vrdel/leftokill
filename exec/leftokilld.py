#!/usr/bin/python

from leftokill import config
from leftokill import core
from leftokill import log
import argparse
import daemon

conffile = '/etc/leftokill/leftokill.conf'

def main():
    lobj = log.Logger()
    logger = lobj.get()

    confopts = config.parse_config(conffile, logger)

    for l in confopts['logmode']:
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
            core.run(confopts, logger)
        except KeyboardInterrupt:
            raise SystemExit(1)
    else:
        context_daemon = daemon.DaemonContext()
        with context_daemon:
            core.run(confopts, logger)

main()
