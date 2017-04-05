# -*- coding:utf8 -*-
# !/usr/bin/env python2

# author          :haiyang.song
# email           :meishild@gmail.com
# datetime        :16/7/21
# version         :1.0
# python_version  :2.7.7
# description     :
# ==============================================================================
import sys
import time
import os

import logging

from net import localip, requests

logger = logging.getLogger("SERVICE")


class DnspodClient:
    def __init__(self, login_token, cli_host, cli_domain):
        self._login_token = login_token
        self._cli_host = cli_host
        self._cli_domain = cli_domain

    def get_domain_id(self):
        response = requests.post_json(self._cli_host, "/Domain.List", dict(
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
            if self._cli_domain == domain_dict['punycode']:
                return domain_dict['id']

    def get_record(self, domain_id, cli_sub_domain):
        response = requests.post_json(self._cli_host, "/Record.List", dict(
            login_token=self._login_token,
            format="json",
            domain_id=domain_id
        ))
        assert response['status'] == 200
        _record_dict = {}
        for record in response['json']['records']:
            if record['type'] == 'A' and record['name'] in cli_sub_domain.split(","):
                _record_dict[record['name']] = record
        return _record_dict

    def set_ddns(self, ip, record_id, domain_id, sub_domain):
        response = requests.post_json(self._cli_host, "/Record.Ddns", dict(
            login_token=self._login_token,
            format="json",
            domain_id=domain_id,
            ip=ip,
            record_id=record_id,
            sub_domain=sub_domain,
            record_line="Default",
        ))
        return response['status'] == 200


class DDNSLoader:
    def __init__(self, config):
        self._config = config

        login_token = "%s,%s" % (self._config.get("dnspod", "id"), self._config.get("dnspod", "token"))
        host = self._config.get("dnspod", "host")
        domain = self._config.get("config", "domain")
        self._cli = DnspodClient(login_token, host, domain)

        self._current_ip = None
        self._domain_id = None
        self._record_dict = {}

    def __refresh(self):
        ip = localip.get_id()
        if ip is None:
            return

        logger.debug("IP:[%s,%s]" % (self._current_ip, ip))
        if self._current_ip == ip:
            logger.debug("SAME IP [%s]. DON'T NEED UPLOAD" % ip)
            return

        for sub_domain, record in self._record_dict.items():
            if ip == record['value']:
                logger.debug("SAME IP [%s]. DON'T NEED UPLOAD" % ip)
                continue

            if self._cli.set_ddns(ip, record['id'], self._domain_id, sub_domain):
                logger.info("[DNSPOD]REFRESH %s DDNS IP [%s --> %s]" % (sub_domain, self._current_ip, ip))
            else:
                logger.error("[DNSPOD]REFRESH DDNS FAIL")

            self._current_ip = ip

    def execute(self):
        logger.info("DDNS SERVER START!")
        self._domain_id = self._cli.get_domain_id()
        self._record_dict = self._cli.get_record(self._domain_id, self._config.get("config", "sub_domain"))

        while True:
            try:
                self.__refresh()
            except Exception as e:
                logger.error(e)
            time.sleep(30)


if __name__ == '__main__':
    path = os.path.split(os.path.realpath(__file__))[0]
    loader = DDNSLoader(path)
    loader.execute()
