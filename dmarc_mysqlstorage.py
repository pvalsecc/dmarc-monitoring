import mysql.connector


def totimestamp(datetime):
    return datetime.strftime('%Y-%m-%d %H:%M:%S')


class DMARCStorage(object):
    def __init__(self, user, password, host, database):
        self._con = mysql.connector.connect(user=user, password=password, host=host, database=database)
        self._cur = self._con.cursor()
        self._init_database()

    def commit(self):
        if self._cur is not None:
            self._con.commit()
            self._cur.close()
            self._con.close()

    def _init_database(self):
        self._cur.execute("""CREATE TABLE IF NOT EXISTS dmarc_reports (
                                report_id VARCHAR(255) PRIMARY KEY,
                                receiver VARCHAR(255),
                                report_filename VARCHAR(255),
                                report_start TIMESTAMP DEFAULT now(),
                                report_end TIMESTAMP DEFAULT now()
                            );""")
        self._cur.execute("""CREATE TABLE IF NOT EXISTS dmarc_records (
                                report_id VARCHAR(255) REFERENCES dmarc_reports(report_id) ON DELETE CASCADE,
                                record_id INTEGER,
                                ip_address VARCHAR(255),
                                hostname VARCHAR(255),
                                disposition VARCHAR(20),
                                reason VARCHAR(20),
                                spf_pass BOOLEAN,
                                dkim_pass BOOLEAN,
                                header_from VARCHAR(255),
                                envelope_from VARCHAR(255),
                                count INTEGER,
                                PRIMARY KEY (report_id, record_id)
                            );""")
        self._cur.execute("""CREATE TABLE IF NOT EXISTS dmarc_spf_results (
                                report_id VARCHAR(255),
                                record_id INTEGER,
                                spf_id INTEGER,
                                domain VARCHAR(255),
                                result VARCHAR(20),
                                PRIMARY KEY (report_id, record_id, spf_id),
                                FOREIGN KEY (report_id, record_id)
                                    REFERENCES dmarc_records(report_id, record_id)
                                    ON DELETE CASCADE
                            );""")
        self._cur.execute("""CREATE TABLE IF NOT EXISTS dmarc_dkim_signatures (
                                report_id VARCHAR(255),
                                record_id INTEGER,
                                signature_id INTEGER,
                                domain VARCHAR(255),
                                result VARCHAR(20),
                                selector VARCHAR(20),
                                human_result VARCHAR(255),
                                PRIMARY KEY (report_id, record_id, signature_id),
                                FOREIGN KEY (report_id, record_id)
                                    REFERENCES dmarc_records(report_id, record_id)
                                    ON DELETE CASCADE,
                                CONSTRAINT unique_dkim_sig
                                    UNIQUE (report_id, record_id, domain, result, selector)
                            );""")

    def save_new_report(self, report):
        # Persist the report itself:
        self._cur.execute("INSERT INTO dmarc_reports VALUES (%s,%s,%s,%s,%s);",
                          [report.id, report.receiver, report.filename,
                           totimestamp(report.start_date), totimestamp(report.end_date)])
        # Persist each record of that report with a generated ID:
        for rec_id, rec in enumerate(report.records):
            self._cur.execute("INSERT INTO dmarc_records VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);",
                              [report.id, rec_id, rec.ip, rec.host, rec.disposition, rec.reason,
                               rec.spf_pass, rec.dkim_pass, rec.header_from, rec.envelope_from,
                               rec.count])
            # Persist the SPF data:
            for spf_id, spf_result in enumerate(rec.spf_results):
                self._cur.execute("INSERT INTO dmarc_spf_results VALUES (%s,%s,%s,%s,%s);",
                                  [report.id, rec_id, spf_id, spf_result["domain"], spf_result["result"]])
            # Persist all the DKIM signatures with generated IDs
            for sig_id, sig in enumerate(rec.dkim_signatures):
                self._cur.execute("INSERT INTO dmarc_dkim_signatures VALUES (%s,%s,%s,%s,%s,%s,%s);",
                                  [report.id, rec_id, sig_id, sig["domain"], sig["result"], sig["selector"], sig["human_result"]])
