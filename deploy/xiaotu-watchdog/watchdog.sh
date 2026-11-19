#!/bin/bash
# 小兔云看门狗：每 30 分钟跑一次（systemd timer），检查各定时任务是否还在正常运行
# 查三类信号：定时器是否 active+enabled；服务上次运行结果是否 success；
# 定时器上次触发 / 日志是否新鲜（静默死亡就靠新鲜度发现）。
# 晨间三件套（briefing/learning/feed）还查日志最后一行：发送失败 / JSON 过期也报警，
# 因为它们的产出就是消息本身，失败了不会有人知道。
# 异常只在状态变化时发一张飞书红卡（多任务异常合并成一张），恢复发绿卡；
# 持续异常每 24 小时重发一次，避免告警被淹没。
# 窗口型任务（mui-notify、sweep-notify）窗口外静默退出，不查日志，只查定时器与上次结果；
# 月/周任务首次运行前（无日志、无触发记录）不报警。
# 中转签到没有 systemd 单元文件时只查日志新鲜度（它可能走 cron）。
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/monitor_common.sh"

ROOT="${WATCHDOG_ROOT:-/root}"
STATE_DIR="$ROOT/watchdog_state"
LOG_FILE="$ROOT/watchdog.log"
HEARTBEAT="$STATE_DIR/heartbeat"
LAST_ALERT="$STATE_DIR/last_alert"
mkdir -p "$STATE_DIR"

log() { echo "[$(now_cn)] $*" >> "$LOG_FILE"; }

NOW_EPOCH="$(date -u +%s)"

if [ -z "${FEISHU_URL:-}" ]; then
  log "WARN: feishu webhook not found, alerts will fail"
fi

# 时长格式化：秒 -> "3 天" / "5 小时" / "20 分钟" / "45 秒"
fmt_age() {
  local s="$1"
  if [ "$s" -ge 86400 ]; then echo "$((s / 86400)) 天"
  elif [ "$s" -ge 3600 ]; then echo "$((s / 3600)) 小时"
  elif [ "$s" -ge 60 ]; then echo "$((s / 60)) 分钟"
  else echo "${s} 秒"
  fi
}

sys() { systemctl "$@" 2>/dev/null; }

timer_active() { sys is-active --quiet "$1"; }
timer_enabled() { sys is-enabled --quiet "$1"; }
svc_result() { sys show -p Result --value "$1"; }
unit_loaded() { [ "$(sys show -p LoadState --value "$1")" = "loaded" ]; }

last_trigger_epoch() {
  local raw epoch
  raw="$(sys show -p LastTriggerUSec --value "$1")"
  [ -z "$raw" ] || [ "$raw" = "n/a" ] && return 1
  epoch="$(date -u -d "$raw" +%s 2>/dev/null)" || return 1
  printf '%s' "$epoch"
}

# check_job <显示名> <timer|-> <service|-> <日志|-> <触发最长间隔秒|0> <日志最长间隔秒|0> <失败特征正则|-> <缺日志是否容忍 0/1>
# 结果写全局变量 CHECK_STATUS（OK/BAD）与 CHECK_REASON
check_job() {
  local name="$1" timer="$2" svc="$3" logf="$4" tmax="$5" lmax="$6" fpat="$7" log_optional="$8"
  local res trig trig_age mtime age last
  CHECK_STATUS="OK"; CHECK_REASON=""
  if [ "$timer" != "-" ]; then
    if ! timer_active "$timer"; then CHECK_STATUS="BAD"; CHECK_REASON="定时器未运行"; return 0; fi
    if ! timer_enabled "$timer"; then CHECK_STATUS="BAD"; CHECK_REASON="定时器未启用"; return 0; fi
  fi
  if [ "$svc" != "-" ]; then
    res="$(svc_result "$svc")"
    if [ -n "$res" ] && [ "$res" != "success" ]; then CHECK_STATUS="BAD"; CHECK_REASON="上次运行失败（$res）"; return 0; fi
  fi
  if [ "$timer" != "-" ] && [ "$tmax" != "0" ]; then
    trig="$(last_trigger_epoch "$timer")"
    if [ -n "$trig" ]; then
      trig_age=$((NOW_EPOCH - trig))
      if [ "$trig_age" -gt "$tmax" ]; then CHECK_STATUS="BAD"; CHECK_REASON="定时器已 $(fmt_age "$trig_age")未触发"; return 0; fi
    fi
  fi
  if [ "$logf" != "-" ]; then
    if [ ! -f "$logf" ]; then
      if [ "$log_optional" != "1" ]; then CHECK_STATUS="BAD"; CHECK_REASON="日志文件不存在"; return 0; fi
    else
      if [ "$lmax" != "0" ]; then
        mtime="$(stat -c %Y "$logf" 2>/dev/null || echo "$NOW_EPOCH")"
        age=$((NOW_EPOCH - mtime))
        if [ "$age" -gt "$lmax" ]; then CHECK_STATUS="BAD"; CHECK_REASON="日志已 $(fmt_age "$age")未更新"; return 0; fi
      fi
      if [ "$fpat" != "-" ]; then
        last="$(tail -n 1 "$logf")"
        if printf '%s' "$last" | grep -qE "$fpat"; then CHECK_STATUS="BAD"; CHECK_REASON="最近一次运行失败：$last"; return 0; fi
      fi
    fi
  fi
}

# check_daemon <显示名> <service>
check_daemon() {
  local name="$1" svc="$2"
  CHECK_STATUS="OK"; CHECK_REASON=""
  if ! sys is-active --quiet "$svc"; then CHECK_STATUS="BAD"; CHECK_REASON="服务未运行"; fi
}

NEW_BAD=""; RECOVERED=""; STILL_BAD=""
NEW_N=0; REC_N=0; STILL_N=0

# track <key> <显示名> <检查函数> <检查函数参数...>
track() {
  local key="$1" disp="$2" fn="$3"; shift 3
  "$fn" "$disp" "$@"
  local prev="UNKNOWN" sf="$STATE_DIR/$key"
  [ -f "$sf" ] && prev="$(head -n 1 "$sf")"
  if [ "$CHECK_STATUS" = "BAD" ]; then
    echo "BAD" > "$sf"
    if [ "$prev" = "BAD" ]; then
      STILL_BAD="$STILL_BAD
• **$disp**：$CHECK_REASON"
      STILL_N=$((STILL_N + 1))
    else
      NEW_BAD="$NEW_BAD
• **$disp**：$CHECK_REASON"
      NEW_N=$((NEW_N + 1))
      log "$disp: $prev -> BAD ($CHECK_REASON)"
    fi
  else
    echo "OK" > "$sf"
    if [ "$prev" = "BAD" ]; then
      RECOVERED="$RECOVERED
• **$disp**"
      REC_N=$((REC_N + 1))
      log "$disp: BAD -> OK"
    fi
  fi
}

# --- 检查清单 ---
# 5 分钟级：触发间隔阈值 15 分钟；20 分钟级：1 小时；日级：26 小时
track monitor "服务器监控" check_job monitor.timer monitor.service "$ROOT/monitor.log" 900 900 "-" 0
track instabox "InstaBox 保活" check_job instabox-keepalive.timer instabox-keepalive.service "-" 3600 0 "-" 0
track mui-notify "m-ui 升级通知" check_job mui-update-notify.timer mui-update-notify.service "-" 900 0 "-" 0
track briefing "早间简报" check_job briefing.timer briefing.service "$ROOT/briefing.log" 93600 93600 "FAILED" 0
track learning "学习消息" check_job learning.timer learning.service "$ROOT/learning.log" 93600 93600 "失败|过期" 0
track feed "Feed 摘要" check_job feed.timer feed.service "$ROOT/feed.log" 93600 93600 "失败|过期" 0
track azure-budget "Azure 预算" check_job azure-budget.timer azure-budget.service "$ROOT/azure-budget/budget.log" 93600 93600 "-" 0
if unit_loaded relay-checkin.timer; then
  track relay-checkin "中转签到" check_job relay-checkin.timer relay-checkin.service "$ROOT/relay-checkin.log" 93600 93600 "-" 0
else
  track relay-checkin "中转签到" check_job "-" "-" "$ROOT/relay-checkin.log" 0 93600 "-" 0
fi
# 月任务：触发阈值 40 天，日志阈值 35 天，首次运行前无日志不报警
track monthly-cleanup "月度清理检查" check_job monthly-cleanup-check.timer monthly-cleanup-check.service "$ROOT/monthly-cleanup-check.log" 3456000 3024000 "-" 1
# 周任务：触发阈值 9 天，窗口外不写日志故不查日志
track sweep-notify "周扫通知" check_job sweep-notify.timer sweep-notify.service "-" 777600 0 "-" 0
# 常驻服务：只查是否在运行
track remind "日期提醒" check_daemon remind.service
track renew "续费提醒" check_daemon renew.service

# 心跳：每次运行都写，供外部确认看门狗本身还活着
date -u +%s > "$HEARTBEAT"

send_alert() {
  if feishu_card "$1" "$2" "小兔云定时任务自检" "$3" "时间：$(now_cn) · 小兔云看门狗" "$4" "$5"; then
    date -u +%s > "$LAST_ALERT"
    return 0
  fi
  log "飞书告警发送失败"
  rm -f "$LAST_ALERT"
  return 1
}

if [ "$NEW_N" -gt 0 ]; then
  body="以下定时任务异常：$NEW_BAD"
  [ -n "$STILL_BAD" ] && body="$body

仍未恢复：$STILL_BAD"
  [ -n "$RECOVERED" ] && body="$body

同时恢复：$RECOVERED"
  if [ "$STILL_N" -gt 0 ]; then
    metric="$(metric_block "新异常" "$NEW_N 项" "仍异常" "$STILL_N 项")"
  else
    metric="$(metric_block "新异常" "$NEW_N 项")"
  fi
  send_alert red "看门狗告警" "$body" "异常" "$metric"
elif [ "$REC_N" -gt 0 ]; then
  send_alert green "看门狗恢复" "以下定时任务已恢复：$RECOVERED" "已恢复" "$(metric_block "已恢复" "$REC_N 项")"
elif [ "$STILL_N" -gt 0 ]; then
  last_alert=0
  [ -f "$LAST_ALERT" ] && last_alert="$(cat "$LAST_ALERT")"
  if [ $((NOW_EPOCH - last_alert)) -ge 86400 ]; then
    send_alert red "看门狗告警" "以下定时任务仍异常（已持续超过 24 小时）：$STILL_BAD" "异常" "$(metric_block "仍异常" "$STILL_N 项")"
  fi
fi

# 日志轮转：只留最后 500 行
if [ -f "$LOG_FILE" ]; then
  tail -n 500 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
fi
