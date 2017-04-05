# -*- coding:utf8 -*-

# author          :haiyang.song
# email           :meishild@gmail.com
# datetime        :2017/4/5
# version         :1.0
# python_version  :3.4.3
# description     :
# ==============================================================================
import os
import logging
import sys


def set_default(log_path="/tmp/temp.log", level="INFO"):
    if not os.access(log_path, os.W_OK):
        sys.stderr.write("Permission denied:%s" % log_path)
        sys.exit(0)

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
