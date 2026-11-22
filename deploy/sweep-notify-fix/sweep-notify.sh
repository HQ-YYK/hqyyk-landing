#!/bin/bash
# 周扫结果通知轮询（小兔云，/root/sweep-notify.sh）
# 定时器每周日 03:30–05:30 UTC 每 15 分钟跑一次；GCP 周扫在周日 03:00 UTC 跑，
# 跑完约 15–25 分钟。脚本读 GCP 状态文件 https://panel.hqyyk.de5.net/sweep-status.json，
# 读到今天的新结果就推一张飞书卡（按日期+状态去重）；窗口结束还没读到就发红卡告警。
# 注意：状态文件由 weekly-sweep.py 经 json.dump(indent=1) 写出，冒号后带空格
# （"date": "2026-..."），下面所有 grep 模式里的冒号后必须留 ` *`，否则解析不到
# （2026-11-22 教训：没留空格导致首轮实跑误报“周扫状态读不到”）。
# shellcheck disable=SC1091
. /root/monitor_common.sh
URL="https://panel.hqyyk.de5.net/sweep-status.json"
STATE_DIR=/root/sweep-notify
STATE_FILE=$STATE_DIR/last
LOG=/root/sweep-notify.log
mkdir -p "$STATE_DIR"
log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; tail -n 300 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; }

# 只在周日 03:30–05:30 UTC 干活
[ "$(date +%u)" = "7" ] || exit 0
utc_date=$(date +%F)
utc_hm=$(date +%H%M)
if [ "$utc_hm" -lt 0330 ] || [ "$utc_hm" -gt 0530 ]; then exit 0; fi

# 清理 7 天前的 seen/alert 标记
find "$STATE_DIR" \( -name 'seen-*' -o -name 'alert-*' \) -mtime +7 -delete 2>/dev/null

body=$(curl -fsSL --max-time 15 "$URL" 2>/dev/null)
if [ -z "$body" ]; then
  log "读取状态文件失败"
else
  at_date=$(printf '%s' "$body" | grep -oE '"date": *"[0-9-]+' | head -1 | cut -d'"' -f4)
  if [ "$at_date" = "$utc_date" ]; then
    touch "$STATE_DIR/seen-$utc_date"
    status=$(printf '%s' "$body" | grep -oE '"status": *"[^"]*"' | head -1 | cut -d'"' -f4)
    alive=$(printf '%s' "$body" | grep -oE '"alive": *[0-9]+' | head -1 | cut -d: -f2 | tr -d ' ')
    imported=$(printf '%s' "$body" | grep -oE '"imported": *[0-9]+' | head -1 | cut -d: -f2 | tr -d ' ')
    final=$(printf '%s' "$body" | grep -oE '"final": *[0-9]+' | head -1 | cut -d: -f2 | tr -d ' ')
    cleanup_del=$(printf '%s' "$body" | grep -oE '"cleanup_deleted": *[0-9]+' | head -1 | cut -d: -f2 | tr -d ' ')
    survivors=$(printf '%s' "$body" | grep -oE '"survivors_text": *"[^"]*"' | head -1 | cut -d'"' -f4)
    degraded=$(printf '%s' "$body" | grep -oE '"degraded_text": *"[^"]*"' | head -1 | cut -d'"' -f4)
    errors=$(printf '%s' "$body" | grep -oE '"errors_text": *"[^"]*"' | head -1 | cut -d'"' -f4)
    last_notified=$(cat "$STATE_FILE" 2>/dev/null || echo "")
    if [ "$status" = "ok" ]; then
      key="ok:$utc_date:$alive:$imported"
      if [ "$last_notified" != "$key" ]; then
        extra=""
        [ -n "$degraded" ] && extra="（降级：$degraded）"
        if [ "${alive:-0}" -gt 0 ]; then
          feishu_card green "周扫完成：新活节点 ${alive} 个" "每周节点轮换" "本轮信誉过关 ${final:-?} 条，导入 ${imported:-?} 条，测速存活 **${alive}** 条，已留在面板（0 分配，需手动分给 ces）：$survivors。清理删掉 ${cleanup_del:-0} 条旧死节点。$extra" "" "有新节点" "$(metric_block 存活 "$alive" 导入 "$imported")"
        else
          feishu_card orange "周扫完成：本轮无存活节点" "每周节点轮换" "本轮信誉过关 ${final:-?} 条，导入 ${imported:-?} 条，测速全部不通，已删干净。清理删掉 ${cleanup_del:-0} 条旧死节点。$extra" "" "无存活" "$(metric_block 存活 0 导入 "$imported")"
        fi
        echo "$key" > "$STATE_FILE"
      fi
    elif [ "$status" = "error" ]; then
      key="error:$utc_date:$errors"
      if [ "$last_notified" != "$key" ]; then
        feishu_card red "周扫失败" "每周节点轮换" "本轮周扫中途失败，请检查 GCP 日志 /root/node-sweep/sweep.log。错误：$errors" "" "失败" ""
        echo "$key" > "$STATE_FILE"
      fi
    else
      log "未知状态：$status"
    fi
  else
    log "状态文件过期（date=$at_date，今天 $utc_date），视为 GCP 定时未跑"
  fi
fi

# 窗口结束（05:30 UTC）时若全程没读到今天的有效状态，发一次告警
if [ "$utc_hm" -ge 0525 ] && [ ! -f "$STATE_DIR/seen-$utc_date" ] && [ ! -f "$STATE_DIR/alert-$utc_date" ]; then
  feishu_card red "周扫状态读不到" "每周节点轮换" "本轮窗口内始终没读到 GCP 今天的周扫状态，请检查 GCP 定时任务与 nginx 状态文件配置。" "" "异常" ""
  touch "$STATE_DIR/alert-$utc_date"
  log "窗口结束未读到有效状态，已发告警"
fi
