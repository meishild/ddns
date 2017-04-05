# -*- coding:utf8 -*-

# author          :haiyang.song
# email           :meishild@gmail.com
# datetime        :2017/4/5
# version         :1.0
# python_version  :3.4.3
# description     :
# ==============================================================================
import re
import urllib

import logging

logger = logging.getLogger('NETWORK')


def _request_get_ip(url):
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
