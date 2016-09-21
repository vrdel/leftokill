#!/usr/bin/python

import sys
import os
import time
import daemon
import argparse
import pwd

def daemonfunc():
    while True:
        time.sleep(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', dest='user', type=str, required=True)
    args = parser.parse_args()

    try:
        uid, gid = pwd.getpwnam(args.user)[2], pwd.getpwnam(args.user)[3]
    except KeyError as e:
        print e
        raise SystemExit(1)

    d = daemon.DaemonContext(uid=uid, gid=gid)

    with d:
        daemonfunc()

main()
