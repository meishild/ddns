# ddns
通过ubnt配置ddns

需要配置ddns命令执行：

```cmd
configure

set system task-scheduler task task_ddns
set system task-scheduler task task_ddns executable path /usr/bin/python
set system task-scheduler task task_ddns executable arguments "/home/ubnt/ddns/ddns_dnspod.py"
set system task-scheduler task task_ddns interval 1m

commit
save
```