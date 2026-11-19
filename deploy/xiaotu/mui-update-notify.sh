#!/bin/bash
# m-ui 升级通知轮询（小兔云，/root/mui-update-notify.sh）
# 定时器每 5 分钟跑一次；脚本只在 UTC 偶数月 1 号 03:00–05:30（北京时间 11:00–13:30）的窗口内干活，其余时间直接退出。
# 读 GCP 状态文件 https://panel.hqyyk.de5.net/mui-update.json，状态变化时推飞书：
# pending → 橙卡（15 分钟后自动升级）；done → 绿卡；failed → 红卡；up-to-date/skipped → 静默。
# 状态文件的 at 日期不是今天时视为过期（GCP 定时没跑），窗口结束时发一次红卡告警。
# shellcheck disable=SC1091
. /root/monitor_common.sh
URL="https://panel.hqyyk.de5.net/mui-update.json"
STATE_DIR=/root/mui-update-notify
STATE_FILE=$STATE_DIR/last
LOG=/root/mui-update-notify.log
mkdir -p "$STATE_DIR"
log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; tail -n 300 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; }

# UTC（小兔云与 GCP 均为 UTC；检查在 UTC 1 号 03:00 跑）：日期、月份、时分
utc_date=$(date +%F)
utc_month=$(date +%m)
utc_hm=$(date +%H%M)
case "$utc_month" in
  02|04|06|08|10|12) ;;
  *) exit 0 ;;
esac
[ "$(date +%d)" = "01" ] || exit 0
if [ "$utc_hm" -lt 0300 ] || [ "$utc_hm" -gt 0530 ]; then exit 0; fi

# 清理 7 天前的 seen/alert 标记
find "$STATE_DIR" -name 'seen-*' -o -name 'alert-*' -mtime +7 -delete 2>/dev/null

body=$(curl -fsSL --max-time 15 "$URL" 2>/dev/null)
if [ -z "$body" ]; then
  log "读取状态文件失败"
else
  at_date=$(printf '%s' "$body" | grep -oE '"at":"[0-9-]+' | head -1 | cut -d'"' -f4)
  if [ "$at_date" = "$utc_date" ]; then
    touch "$STATE_DIR/seen-$utc_date"
    status=$(printf '%s' "$body" | grep -oE '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    current=$(printf '%s' "$body" | grep -oE '"current":"[^"]*"' | head -1 | cut -d'"' -f4)
    latest=$(printf '%s' "$body" | grep -oE '"latest":"[^"]*"' | head -1 | cut -d'"' -f4)
    last_notified=$(cat "$STATE_FILE" 2>/dev/null || echo "")
    case "$status" in
      pending)
        if [ "$last_notified" != "pending:$latest" ]; then
          feishu_card orange "m-ui 需要升级" "自动升级定时" "m-ui 有新稳定版：**$current → $latest**。15 分钟后自动开始升级，升级期间 VPN 会短暂中断，升完会再通知。" "" "待升级" "$(metric_block 当前版本 "$current")"
          echo "pending:$latest" > "$STATE_FILE"
        fi
        ;;
      done)
        if [ "$last_notified" != "done:$latest" ]; then
          feishu_card green "m-ui 升级完成" "自动升级定时" "m-ui 已从 **$current** 升级到 **$latest**，面板已验证正常。如升到 0.7.17 及以上，记得抽空在面板设置里确认「受信任的反向代理」已填（面板在 nginx 后面）。" "" "已完成" "$(metric_block 新版本 "$latest")"
          echo "done:$latest" > "$STATE_FILE"
        fi
        ;;
      failed)
        if [ "$last_notified" != "failed:$latest" ]; then
          reason=$(printf '%s' "$body" | grep -oE '"reason":"[^"]*"' | head -1 | cut -d'"' -f4)
          feishu_card red "m-ui 自动升级失败" "自动升级定时" "m-ui 从 **$current** 升到 **$latest** 失败，请手动检查。原因：$reason" "" "失败" "$(metric_block 目标版本 "$latest")"
          echo "failed:$latest" > "$STATE_FILE"
        fi
        ;;
      up-to-date|skipped)
        log "状态 $status，无需通知"
        ;;
      *)
        log "未知状态：$status"
        ;;
    esac
  else
    log "状态文件过期（at=$at_date，今天 $utc_date），视为 GCP 定时未跑"
  fi
fi

# 窗口结束（05:30 UTC）时若全程没读到今天的有效状态，发一次告警
if [ "$utc_hm" -ge 0525 ] && [ ! -f "$STATE_DIR/seen-$utc_date" ] && [ ! -f "$STATE_DIR/alert-$utc_date" ]; then
  feishu_card red "m-ui 升级状态读不到" "自动升级定时" "本轮窗口内始终没读到 GCP 今天的 m-ui 升级状态，请检查 GCP 定时任务与 nginx 状态文件配置。" "" "异常" ""
  touch "$STATE_DIR/alert-$utc_date"
  log "窗口结束未读到有效状态，已发告警"
fi
