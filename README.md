# ddns
通过dnspod动态修改域名对应的ip。
需要在dnspod申请token

## CMD
start: `python ddns.py start`

restart: `python ddns.py restart`

stop: `python ddns.py stop`

## DEBUG
debug模式不会创建pid文件，只会在前台执行不会进行守护。
`python ddns.py debug'