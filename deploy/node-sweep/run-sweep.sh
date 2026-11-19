#!/bin/bash
# 周扫启动器（GCP /root/node-sweep/run-sweep.sh）
# 跑 weekly-sweep.py，跑完把 status.json 拷到 nginx 状态文件目录（/var/www/html，
# 与 cleanup-status.json 同目录；nginx 里有对应的 /sweep-status.json location），
# 供小兔云 sweep-notify.sh 轮询发飞书。GCP 本机脚本不存飞书 webhook。
# 注意：不要再用“目录里有 mui-update.json”做判断——mui-update.json 由双月 1 号的
# 检查任务生成，12-01 之前不存在，曾导致 2026-11-19 实跑后文件没发布出去。
set -u
cd /root/node-sweep || exit 1
/usr/bin/python3 weekly-sweep.py "$@"
rc=$?
if [ -f status.json ]; then
  for dir in /var/www/html /usr/share/nginx/html /var/www /srv/www /usr/local/nginx/html; do
    if [ -d "$dir" ]; then
      cp status.json "$dir/sweep-status.json" 2>/dev/null && \
        echo "$(date '+%F %T') status.json published to $dir/sweep-status.json" >> sweep.log
      break
    fi
  done
fi
exit $rc
