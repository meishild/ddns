# -*- coding:utf8 -*-
# !/usr/bin/env python2

# author          :haiyang.song
# email           :meishild@gmail.com
# datetime        :16/7/21
# version         :1.0
# python_version  :2.7.7
# description     :
# ==============================================================================
import ConfigParser
import httplib
import json
import re
import sys
import time
import logging
import os
import urllib

logger = logging.getLogger('[PythonService]')


class DDNSLoader:
    def __init__(self):
        self._domain_id = None
        self._current_ip = None
        self._record_dict = {}
        self._config = None
        self._login_token = None
        self.load_config()
        self.init_logger()

    def load_config(self):
        path = os.path.split(os.path.realpath(__file__))[0] + '/config.cnf'
        self._config = ConfigParser.ConfigParser()
        if not os.path.exists(path):
            print("Config is not exist!!!")
            sys.exit(0)
        self._config.read(path)
        self._login_token = ("%s,%s" % (self._config.get("dnspod", "id"), self._config.get("dnspod", "token")))

    def init_logger(self):
        dir_path = self._config.get("config", "log_path")
        handler = logging.FileHandler(os.path.join(dir_path, "ddns.log"))

        formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-4s %(message)s')
        handler.setFormatter(formatter)

        logger.addHandler(handler)
        conf_log_level = self._config.get("config", "log_level")
        log_level = logging.INFO
        level_dict = {
            'debug': logging.DEBUG,
            'error': logging.ERROR,
            'info': logging.INFO,
            'warn': logging.WARN
        }
        conf_log_level = level_dict.get(conf_log_level)
        if conf_log_level is not None:
            log_level = conf_log_level

        logger.setLevel(log_level)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    def post_json(self, req_api, params):
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/json"}
        conn = httplib.HTTPSConnection(self._config.get("dnspod", "host"))
        conn.request("POST", req_api, urllib.urlencode(params), headers)
        response = conn.getresponse()
        date = response.read()
        return dict(
            status=response.status,
            reason=response.reason,
            json=json.loads(date)
        )

    def get_domain(self):
        if self._domain_id is not None:
            return

        response = self.post_json("/Domain.List", dict(
            login_token=self._login_token,
            format="json"
        ))
        assert response['status'] == 200
        if "domains" not in response['json']:
            logger.error("[DNSPOD]Login Error:" + response['json']['status']['message'])
            sys.exit(0)

        domains = response['json']['domains']
        logger.debug("[DNSPOD]LOAD DOMAINS:%s" % domains)
        if len(domains) < 1:
            logger.error("[DNSPOD]not Config domain!!")
            sys.exit(0)

        for domain_dict in response['json']['domains']:
            if self._config.get("config", "domain") == domain_dict['punycode']:
                self._domain_id = domain_dict['id']

    def _get_ip(self, url):
        try:
            response = urllib.urlopen(url).read()
            logger.debug("GET IP RESPONSE:%s" % response)
            pattern = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
            find_list = pattern.findall(response)
            if len(find_list) != 1:
                logger.warn("NOT GET GATEWAY IP.")
                return None
            logger.debug("GET IP %s", find_list[0])
            return find_list[0]
        except Exception as e:
            logger.error("[GET IP ERROR]" + e.message)
            return None

    def get_id(self):
        ip_get_list = [
            "http://ip.chinaz.com/getip.aspx",
            "http://ip.taobao.com/service/getIpInfo2.php?ip=myip"
        ]

        for url in ip_get_list:
            ip = self._get_ip(url)
            if ip is not None:
                return ip
        logger.error("NETWORK ERROR!!!")
        return None

    def get_record(self):
        response = self.post_json("/Record.List", dict(
            login_token=self._login_token,
            format="json",
            domain_id=self._domain_id
        ))
        assert response['status'] == 200
        for record in response['json']['records']:
            if record['type'] == 'A' and record['name'] in self._config.get("config", "sub_domain").split(","):
                self._record_dict[record['name']] = record

    def ddns(self, ip, record_id, sub_domain):
        response = self.post_json("/Record.Ddns", dict(
            login_token=self._login_token,
            format="json",
            domain_id=self._domain_id,
            ip=ip,
            record_id=record_id,
            sub_domain=sub_domain,
            record_line="Default",
        ))
        return response['status'] == 200

    def start(self):
        logger.info("DDNS SERVER START!")
        while True:
            try:
                if self._domain_id is None:
                    self.get_domain()
                if len(self._record_dict) == 0:
                    self.get_record()

                self.refresh()
            except Exception as e:
                logger.error(e)
            time.sleep(30)

    def refresh(self):
        ip = self.get_id()
        if ip is None:
            return

        logger.debug("IP:[%s,%s]" % (self._current_ip, ip))
        if self._current_ip != ip:
            for sub_domain, record in self._record_dict.items():
                if ip == record['value']:
                    logger.debug("SAME IP [%s]. DON'T NEED UPLOAD" % ip)
                    continue
                if self.ddns(ip, record['id'], sub_domain):
                    self._current_ip = ip
                    logger.info("[DNSPOD]REFRESH %s DDNS IP [%s --> %s]" % (sub_domain, self._current_ip, ip))
                else:
                    logger.info("[DNSPOD]REFRESH DDNS FAIL")

            self._current_ip = ip
        else:
            logger.debug("SAME IP [%s]. DON'T NEED UPLOAD" % ip)


def daemonize(stdin='/dev/null', stdout='/dev/null', stderr='dev/null'):
    """
    Fork当前进程为守护进程，重定向标准文件描述符（默认情况下定向到/dev/null）
    """
    # Perform first fork.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # first parent out
    except OSError, e:
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    # 从母体环境脱离
    os.chdir("/")
    os.umask(0)
    os.setsid()
    # 执行第二次fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # second parent out
    except OSError, e:
        sys.stderr.write("fork #2 failed: (%d) %s]n" % (e.errno, e.strerror))
        sys.exit(1)

    # 进程已经是守护进程了，重定向标准文件描述符
    for f in sys.stdout, sys.stderr: f.flush()
    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


if __name__ == '__main__':
    daemonize()
    DDNSLoader().start()
