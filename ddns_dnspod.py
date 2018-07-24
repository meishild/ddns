# -*- coding:utf8 -*-
# !/usr/bin/env python2

# author          :haiyang.song
# email           :meishild@gmail.com
# datetime        :16/7/21
# version         :1.0
# python_version  :2.7.7
# description     :
# ==============================================================================
import httplib
import json
import os
import re
import socket
import urllib
from time import sleep
import logging

logger = logging.getLogger("SERVICE")
socket.setdefaulttimeout(2.0)


def set_default(log_path="/tmp/temp.log", level="INFO"):
    set_logger = logging.getLogger('SERVICE')
    handler = logging.FileHandler(log_path)
    formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-4s %(message)s')
    handler.setFormatter(formatter)

    set_logger.addHandler(handler)

    log_level = logging.INFO
    level_dict = {
        'debug': logging.DEBUG,
        'error': logging.ERROR,
        'info': logging.INFO,
        'warn': logging.WARN
    }
    conf_log_level = level_dict.get(level)
    if conf_log_level is not None:
        log_level = conf_log_level

    set_logger.setLevel(log_level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    set_logger.addHandler(console_handler)
    return set_logger


def _request_get_ip(url):
    try:
        response = urllib.urlopen(url).read()
        logger.debug("GET IP RESPONSE:%s" % response)
        pattern = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        find_list = pattern.findall(response)
        if len(find_list) != 1:
            logger.warn("NOT GET GATEWAY IP.")
            return None
        return find_list[0]
    except Exception as e:
        logger.error("[GET IP ERROR]" + e.message)
        return None


def post_json(host, req_api, params, retry_times=3):
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/json"}
    for i in range(0, retry_times, 1):

        try:
            conn = httplib.HTTPSConnection(host, timeout=2)
            conn.request("POST", req_api, urllib.urlencode(params), headers)
            response = conn.getresponse()
            date = response.read()
            return True, dict(
                status=response.status,
                reason=response.reason,
                json=json.loads(date)
            )

        except Exception as _:
            logger.error("REQUEST ERROR:%s" % req_api)
        sleep(3)
    return False, None


def get_id():
    ip_get_list = [
        "http://ip.chinaz.com/getip.aspx",
        "http://ip.taobao.com/service/getIpInfo2.php?ip=myip"
    ]

    for url in ip_get_list:
        ip = _request_get_ip(url)
        if ip is not None:
            return ip
    logger.error("NETWORK ERROR!!!")
    return None


def _dnspod_post(host, req_api, params):
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/json"}

    try:
        conn = httplib.HTTPSConnection(host, timeout=2)
        conn.request("POST", req_api, urllib.urlencode(params), headers)
        response = conn.getresponse()
        json_data = json.loads(response.read())

        if response.status == 200:
            if "status" in json_data:
                if json_data.get("status").get("code") != "1":
                    logger.error("REQUEST ERROR:%s" % json_data.get("message"))
        return json_data

    except Exception as _:
        logger.error("REQUEST ERROR:%s" % req_api)


class DnspodClient:
    def __init__(self, login_token, cli_host, cli_domain):
        self._login_token = login_token
        self._cli_host = cli_host
        self._cli_domain = cli_domain

    def get_domain_id(self):
        response = _dnspod_post(self._cli_host, "/Domain.List", dict(
            login_token=self._login_token,
            format="json"
        ))
        if "domains" not in response:
            logger.error("[DNSPOD]Login Error:" + response['status']['message'])

        domains = response['domains']
        logger.debug("[DNSPOD]LOAD DOMAINS:%s" % domains)
        if len(domains) < 1:
            logger.error("[DNSPOD]not Config domain!!")

        for domain_dict in response['domains']:
            if self._cli_domain == domain_dict['punycode']:
                return domain_dict['id']

    def get_record(self, domain_id, cli_sub_domain):
        response = _dnspod_post(self._cli_host, "/Record.List", dict(
            login_token=self._login_token,
            format="json",
            domain_id=domain_id
        ))

        _record_dict = {}
        for record in response['records']:
            if record['type'] == 'A' and record['name'] in cli_sub_domain.split(","):
                _record_dict[record['name']] = record
        return _record_dict

    def set_ddns(self, ip, record_id, domain_id, sub_domain):
        response = _dnspod_post(self._cli_host, "/Record.Ddns", dict(
            login_token=self._login_token,
            format="json",
            domain_id=domain_id,
            ip=ip,
            record_id=record_id,
            sub_domain=sub_domain,
            record_line="默认",
        ))
        logger.debug(response)
        return response.get("status").get("code") == "1"


class DDNSLoader:
    def __init__(self, config):
        self._config = config

        login_token = "%s,%s" % (self._config.get("dnspod", "id"), self._config.get("dnspod", "token"))
        host = self._config.get("dnspod", "host")
        domain = self._config.get("config", "domain")
        self._cli = DnspodClient(login_token, host, domain)

        self._domain_id = None

    def __refresh(self):
        ip = get_id()
        if ip is None:
            return

        record_dict = self._cli.get_record(self._domain_id, self._config.get("config", "sub_domain"))
        for sub_domain, record in record_dict.items():
            if ip == record['value']:
                logger.info("[DNSPOD]SAME IP [%s -> %s]. DON'T NEED UPLOAD" % (sub_domain, ip))
                continue

            if self._cli.set_ddns(ip, record['id'], self._domain_id, sub_domain):
                logger.info("[DNSPOD]REFRESH %s DDNS IP [%s --> %s]" % (sub_domain, record['value'], ip))
            else:
                logger.error("[DNSPOD]REFRESH DDNS FAIL")

    def execute(self):
        logger.info("DDNS SERVER START!")

        try:
            if self._domain_id is None:
                self._domain_id = self._cli.get_domain_id()

            self.__refresh()
        except Exception as e:
            logger.error(e)


if __name__ == '__main__':
    import ConfigParser
    import sys

    config = ConfigParser.ConfigParser()
    try:
        config.read('%s/config.cnf.bak' % os.path.split(os.path.realpath(__file__))[0])
    except Exception as _:
        sys.stderr.write("Config is not exist!!!")

    log_path = config.get("config", "log_path")
    log_level = config.get("config", "log_level")
    set_default(log_path, log_level)

    loader = DDNSLoader(config)
    loader.execute()
