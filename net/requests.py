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

import sys

import logging

logger = logging.getLogger('NETWORK')


def post_json(host, req_api, params):
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/json"}
    try:
        conn = httplib.HTTPSConnection(host)
        conn.request("POST", req_api, urllib.urlencode(params), headers)
        response = conn.getresponse()
        date = response.read()
    except Exception as _:
        logger.error("REQUEST ERROR:%s" % req_api)
        sys.exit(0)

    return dict(
        status=response.status,
        reason=response.reason,
        json=json.loads(date)
    )
