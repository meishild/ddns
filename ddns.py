# -*- coding:utf8 -*-

# author          :haiyang.song
# email           :meishild@gmail.com
# datetime        :2017/4/5
# version         :1.0
# python_version  :3.4.3
# description     :
# ==============================================================================
import ConfigParser
import os
import sys
import log
from daemon import Daemon
from ddns_dnspod import DDNSLoader


def _get_config(cfg_path):
    config = ConfigParser.ConfigParser()
    try:
        config.read('%s/config.cnf' % cfg_path)
    except Exception as _:
        sys.stderr.write("Config is not exist!!!")
    return config


if __name__ == '__main__':
    path = os.path.split(os.path.realpath(__file__))[0]
    config = _get_config(path)
    loader = DDNSLoader(config)

    pid = config.get("config", "pid")
    log_path = config.get("config", "log_path")
    log_level = config.get("config", "log_level")
    log.set_default(log_path, log_level)

    d = Daemon(pid, loader.execute, stdout=log_path)

    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            d.start()
        elif 'stop' == sys.argv[1]:
            d.stop()
        elif 'restart' == sys.argv[1]:
            d.restart()
        elif 'debug' == sys.argv[1]:
            loader.execute()
        else:
            print('unknown command')
            sys.exit(2)
        sys.exit(0)
    else:
        print('usage: %s start|stop|restart|debug' % sys.argv[0])
        sys.exit(2)
