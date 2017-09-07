# -*- coding:utf8 -*-

# author          :haiyang.song
# email           :meishild@gmail.com
# datetime        :2017/4/5
# version         :1.0
# python_version  :3.4.3
# description     :
# ==============================================================================
import httplib
import json
import urllib
import logging
from time import sleep

logger = logging.getLogger('NETWORK')


def post_json(host, req_api, params, retry_times=3):
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/json"}
    for i in range(0, retry_times, 1):

        try:
            conn = httplib.HTTPSConnection(host)
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
