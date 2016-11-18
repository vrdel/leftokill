#!/usr/bin/python

import sys
import os
import time
import daemon
import argparse
import pwd
import threading
from multiprocessing import Process

def dummyprochilds():
    p = Process(target=dummyproc)
    p.start()

def dummyproc():
    while True:
        time.sleep(1)

def daemonfunc():
    th_one = threading.Thread(target=dummyproc)
    th_one.daemon = True
    th_one.start()

    th_two = threading.Thread(target=dummyproc)
    th_two.daemon = True
    th_two.start()

    p_one = Process(target=dummyproc)
    p_one.start()

    p_two = Process(target=dummyprochilds)
    p_two.start()

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
