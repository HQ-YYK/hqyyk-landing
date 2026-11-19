#!/bin/bash
# 周扫启动器（GCP /root/node-sweep/run-sweep.sh）
# 跑 weekly-sweep.py，跑完把 status.json 拷到 nginx 状态文件目录（与 mui-update.json 同目录），
# 供小兔云 sweep-notify.sh 轮询发飞书。GCP 本机脚本不存飞书 webhook。
set -u
cd /root/node-sweep || exit 1
/usr/bin/python3 weekly-sweep.py "$@"
rc=$?
if [ -f status.json ]; then
  for dir in /usr/share/nginx/html /var/www/html /var/www /srv/www /usr/local/nginx/html; do
    if [ -f "$dir/mui-update.json" ]; then
      cp status.json "$dir/sweep-status.json" 2>/dev/null && \
        echo "$(date '+%F %T') status.json published to $dir/sweep-status.json" >> sweep.log
      break
    fi
  done
fi
exit $rc
