#!/usr/bin/env python3
import argparse
import os
import sys

from dmarc_imap import parse_email
from dmarc_parser import parse_report
from dmarc_mysqlstorage import DMARCStorage


def __main__():
    options = argparse.ArgumentParser(description="Parse an email from stdin to get the attached DMARC report")
    options.add_argument("-u", "--user", help="mysql user", required=True)
    options.add_argument("-p", "--password", help="mysql password", required=True)
    options.add_argument("-d", "--database", help="mysql database", required=True)
    options.add_argument("-H", "--host", help="address of the mysql server", default='localhost')
    args = options.parse_args()
    reports = []
    report_dir = '/tmp'
    persistent_storage = DMARCStorage(user=args.user, password=args.password, host=args.host, database=args.database)
    if parse_email(sys.stdin.read(), report_dir, reports)[0]:
        for report in reports:
            try:
                parse_report(persistent_storage, report_dir, report)
            finally:
                os.remove(os.path.join(report_dir, report))
        persistent_storage.commit()


if __name__ == "__main__":
    __main__()
