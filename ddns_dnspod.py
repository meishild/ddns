# -*- coding:utf8 -*-
# !/usr/bin/env python2

# author          :haiyang.song
# email           :meishild@gmail.com
# datetime        :16/7/21
# version         :1.0
# python_version  :2.7.7
# description     :
# ==============================================================================
import time
import os

import logging

from net import localip, requests

logger = logging.getLogger("SERVICE")


def _dnspod_post(host, req_api, params):
    status, response = requests.post_json(host, req_api, params)
    if not status:
        raise Exception("REQUEST DNSPOD ERROR!")

    if response.get("status") == 200:
        if "json" in response and "status" in response.get("json"):
            data = response.get("json").get("status")
            if data.get("code") != "1":
                logger.error("REQUEST BIZ ERROR:%s" % data.get("message"))
    return response


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
        assert response['status'] == 200
        if "domains" not in response['json']:
            logger.error("[DNSPOD]Login Error:" + response['json']['status']['message'])

        domains = response['json']['domains']
        logger.debug("[DNSPOD]LOAD DOMAINS:%s" % domains)
        if len(domains) < 1:
            logger.error("[DNSPOD]not Config domain!!")

        for domain_dict in response['json']['domains']:
            if self._cli_domain == domain_dict['punycode']:
                return domain_dict['id']

    def get_record(self, domain_id, cli_sub_domain):
        response = _dnspod_post(self._cli_host, "/Record.List", dict(
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
        response = _dnspod_post(self._cli_host, "/Record.Ddns", dict(
            login_token=self._login_token,
            format="json",
            domain_id=domain_id,
            ip=ip,
            record_id=record_id,
            sub_domain=sub_domain,
            record_line="默认",
        ))
        logger.debug(response.get("json"))
        return response['status'] == 200


class DDNSLoader:
    def __init__(self, config):
        self._config = config

        login_token = "%s,%s" % (self._config.get("dnspod", "id"), self._config.get("dnspod", "token"))
        host = self._config.get("dnspod", "host")
        domain = self._config.get("config", "domain")
        self._cli = DnspodClient(login_token, host, domain)

        self._domain_id = None

    def __refresh(self):
        ip = localip.get_id()
        if ip is None:
            return

        logger.debug("IP:%s" % ip)

        record_dict = self._cli.get_record(self._domain_id, self._config.get("config", "sub_domain"))
        for sub_domain, record in record_dict.items():
            if ip == record['value']:
                logger.debug("SAME IP [%s]. DON'T NEED UPLOAD" % ip)
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
            time.sleep(30)
        except Exception as e:
            logger.error(e)


if __name__ == '__main__':
    import ConfigParser
    import sys
    import log

    config = ConfigParser.ConfigParser()
    try:
        config.read('%s/config.cnf.bak' % os.path.split(os.path.realpath(__file__))[0])
    except Exception as _:
        sys.stderr.write("Config is not exist!!!")

    log_path = config.get("config", "log_path")
    log_level = config.get("config", "log_level")
    log.set_default(log_path, log_level)

    loader = DDNSLoader(config)
    loader.execute()
