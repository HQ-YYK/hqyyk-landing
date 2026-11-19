#!/bin/bash
# 每月清理结果检查（小兔云，/root/monthly-cleanup-check.sh）
# 定时器每月 16 号 05:00 UTC 跑一次，检查 15 号三台机器的每月清理结果，发一张飞书卡。
# GCP：读 https://panel.hqyyk.de5.net/cleanup-status.json（GCP 清理脚本写的状态文件）
# 华为云：SSH（/root/huawei-sg-key.pem，root@111.91.16.60）读 /var/log/huawei-cleanup.log
# Azure：SSH（/root/azure-check-key，azureuser@13.78.14.46）读 /var/log/azure-cleanup.log
# 状态只按退出码/文件内容判定，不靠中文匹配（小兔云上中文匹配不可靠）。
# shellcheck disable=SC1091
. /root/monitor_common.sh

GCP_URL="https://panel.hqyyk.de5.net/cleanup-status.json"
HUAWEI_KEY=/root/huawei-sg-key.pem
HUAWEI_HOST="root@111.91.16.60"
AZURE_KEY=/root/azure-check-key
AZURE_HOST="azureuser@13.78.14.46"
LOG=/root/monthly-cleanup-check.log
SENT=/root/monthly-cleanup-check.sent
log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; tail -n 300 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; }

# --- 目标日期：要检查的那个 15 号（今天 16 号及以后取本月 15 号；否则取上月 15 号，
#     覆盖 Persistent 迟发 / 手动早跑的情况）---
TODAY=$(date -u +%F)
DAY=$(date -u +%d)
if [ "$DAY" -ge 16 ]; then
  TARGET="${TODAY%-*}-15"
else
  TARGET=$(date -u -d "$TODAY -1 month" +%Y-%m-15)
fi

# 已发过本月的卡就跳过（防重复发送；手动重跑先删 SENT 文件）
if [ -f "$SENT" ] && [ "$(cat "$SENT" 2>/dev/null)" = "$TARGET" ]; then
  log "本月（$TARGET）已发过卡，跳过"
  exit 0
fi

# --- 容量换算 ---
# "6.4G"/"512M"/"900K"/"123" -> KB（整数）
to_kb() {
  local v="$1" u n
  u="${v##*[0-9.]}"
  n="${v%$u}"
  case "$u" in
    T) awk -v n="$n" 'BEGIN{printf "%d", n*1073741824}' ;;
    G) awk -v n="$n" 'BEGIN{printf "%d", n*1048576}' ;;
    M) awk -v n="$n" 'BEGIN{printf "%d", n*1024}' ;;
    K|"") awk -v n="$n" 'BEGIN{printf "%d", n}' ;;
    *) echo 0 ;;
  esac
}

# KB -> 人类可读（>=1G 一位小数 G，否则 M，否则 K；负数带 - 号）
fmt_kb() {
  local kb="$1"
  if [ "$kb" -lt 0 ]; then printf '-'; kb=$(( -kb )); fi
  if [ "$kb" -ge 1048576 ]; then
    awk -v k="$kb" 'BEGIN{printf "%.1fG", k/1048576}'
  elif [ "$kb" -ge 1024 ]; then
    awk -v k="$kb" 'BEGIN{printf "%dM", k/1024}'
  else
    printf '%dK' "$kb"
  fi
}

# 释放详情：freed_detail <df前可用> <df后可用> -> "释放 35M" 或 "剩余 59G"
freed_detail() {
  local b a f
  [ -n "$2" ] || { printf '（无磁盘信息）'; return; }
  b=$(to_kb "$1"); a=$(to_kb "$2")
  f=$((a - b))
  if [ "$f" -gt 0 ]; then printf '释放 %s' "$(fmt_kb "$f")"; else printf '剩余 %s' "$2"; fi
}

# --- 日志分析 ---
# analyze_log <日志文本>：输出 "<最后运行日期> <状态>" 或 "none"
# 状态：ok（有结束行）/ degraded（apt update 两次失败，即清理脚本退出非零）/ interrupted（有开始无结束）
analyze_log() {
  local text="$1" last_date block
  last_date=$(printf '%s' "$text" | grep 'monthly cleanup start ===' | tail -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)
  [ -z "$last_date" ] && { echo "none"; return; }
  block=$(printf '%s' "$text" | awk '/monthly cleanup start ===/{b=""} {b=b"\n"$0} END{print b}')
  if printf '%s' "$block" | grep -q 'apt update: FAILED twice'; then
    echo "$last_date degraded"
  elif printf '%s' "$block" | grep -q 'monthly cleanup end ==='; then
    echo "$last_date ok"
  else
    echo "$last_date interrupted"
  fi
}

# last_block <日志文本>：取最后一次运行的日志块（从最后一个 start 行到末尾）
last_block() {
  printf '%s' "$1" | awk '/monthly cleanup start ===/{b=""} {b=b"\n"$0} END{print b}'
}

# df_avail <日志块> <before|after>：取 "df before:"/"df after:" 行里的可用空间（如 59G）
df_avail() {
  printf '%s' "$1" | grep "df $2:" | grep -oE '[0-9.]+[KMGT] avail' | head -1 | awk '{print $1}'
}

# --- SSH ---
if command -v ssh >/dev/null 2>&1; then SSH_OK=1; else SSH_OK=0; fi

# ssh_fetch <密钥> <主机> <日志路径>：输出日志尾部（最多 200 行）；失败返回非零
ssh_fetch() {
  timeout 60 ssh -i "$1" -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new "$2" "tail -n 200 $3" 2>/dev/null
}

# check_ssh_leg <密钥> <主机> <日志路径>：结果写全局变量
# LEG_STATUS：ok/degraded/interrupted/notrun/unknown；LEG_DETAIL：一行详情；
# LEG_EVIDENCE：面板证据；LEG_FREED_KB：释放的 KB
check_ssh_leg() {
  local key="$1" host="$2" logpath="$3" out rc result rdate rstatus block b a
  LEG_STATUS="unknown"; LEG_DETAIL=""; LEG_EVIDENCE=""; LEG_FREED_KB=0
  if [ "$SSH_OK" != "1" ]; then
    LEG_DETAIL="小兔云未装 SSH 客户端"; LEG_EVIDENCE="command -v ssh 失败"; return
  fi
  if [ ! -f "$key" ]; then
    LEG_DETAIL="密钥未部署"; LEG_EVIDENCE="密钥文件 $key 不存在"; return
  fi
  out=$(ssh_fetch "$key" "$host" "$logpath"); rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$out" ]; then
    LEG_DETAIL="SSH 连接失败"; LEG_EVIDENCE="ssh 退出码 $rc"; return
  fi
  result=$(analyze_log "$out")
  if [ "$result" = "none" ]; then
    LEG_STATUS="notrun"; LEG_DETAIL="日志里没有清理记录"
    LEG_EVIDENCE=$(printf '%s' "$out" | tail -5)
    return
  fi
  rdate="${result%% *}"; rstatus="${result##* }"
  if [ "$rdate" != "$TARGET" ]; then
    LEG_STATUS="notrun"; LEG_DETAIL="日志最后一次是 $rdate"
    LEG_EVIDENCE=$(printf '%s' "$out" | tail -5)
    return
  fi
  block=$(last_block "$out")
  b=$(df_avail "$block" before); a=$(df_avail "$block" after)
  case "$rstatus" in
    ok)
      LEG_STATUS="ok"
      LEG_DETAIL=$(freed_detail "$b" "$a")
      LEG_FREED_KB=$(( $(to_kb "$a") - $(to_kb "$b") ))
      ;;
    degraded)
      LEG_STATUS="degraded"
      LEG_DETAIL="apt 更新失败，源列表未重建"
      ;;
    interrupted)
      LEG_STATUS="interrupted"
      LEG_DETAIL="开始了但没跑完（无结束行）"
      ;;
  esac
  LEG_EVIDENCE=$(printf '%s' "$block" | grep -E 'df after:|FAILED|end ===' | tail -5)
}

# --- GCP：读状态 JSON（3 次重试）---
gcp_body=""
for i in 1 2 3; do
  gcp_body=$(curl -fsSL --max-time 30 "$GCP_URL" 2>/dev/null) && [ -n "$gcp_body" ] && break
  sleep 10
done
GCP_STATUS="unknown"; GCP_DETAIL=""; GCP_EVIDENCE=""; GCP_FREED_KB=0
if [ -z "$gcp_body" ]; then
  GCP_DETAIL="状态文件拉不到"; GCP_EVIDENCE="curl 3 次失败"
else
  gcp_date=$(printf '%s' "$gcp_body" | grep -oE '"date": *"[^"]*"' | head -1 | sed 's/"date": *"//;s/"$//')
  gcp_status=$(printf '%s' "$gcp_body" | grep -oE '"status": *"[^"]*"' | head -1 | sed 's/"status": *"//;s/"$//')
  gcp_freed=$(printf '%s' "$gcp_body" | grep -oE '"freed": *"[^"]*"' | head -1 | sed 's/"freed": *"//;s/"$//')
  GCP_EVIDENCE="$gcp_body"
  if [ -z "$gcp_date" ]; then
    GCP_DETAIL="状态文件格式不对"
  elif [ "$gcp_date" != "$TARGET" ]; then
    GCP_STATUS="notrun"; GCP_DETAIL="状态文件日期是 $gcp_date"
  elif [ "$gcp_status" = "ok" ]; then
    GCP_STATUS="ok"
    if [ -n "$gcp_freed" ] && [ "$gcp_freed" != "?" ]; then
      GCP_DETAIL="释放 $gcp_freed"; GCP_FREED_KB=$(to_kb "$gcp_freed")
    else
      GCP_DETAIL="完成"
    fi
  elif [ "$gcp_status" = "degraded" ]; then
    GCP_STATUS="degraded"; GCP_DETAIL="apt 更新失败，源列表未重建"
  else
    GCP_DETAIL="状态值未知：$gcp_status"
  fi
fi

# --- 华为云 / Azure ---
check_ssh_leg "$HUAWEI_KEY" "$HUAWEI_HOST" /var/log/huawei-cleanup.log
HW_STATUS="$LEG_STATUS"; HW_DETAIL="$LEG_DETAIL"; HW_EVIDENCE="$LEG_EVIDENCE"; HW_FREED_KB="$LEG_FREED_KB"
check_ssh_leg "$AZURE_KEY" "$AZURE_HOST" /var/log/azure-cleanup.log
AZ_STATUS="$LEG_STATUS"; AZ_DETAIL="$LEG_DETAIL"; AZ_EVIDENCE="$LEG_EVIDENCE"; AZ_FREED_KB="$LEG_FREED_KB"

ok_count=0
[ "$GCP_STATUS" = "ok" ] && ok_count=$((ok_count+1))
[ "$HW_STATUS" = "ok" ] && ok_count=$((ok_count+1))
[ "$AZ_STATUS" = "ok" ] && ok_count=$((ok_count+1))
total_kb=$((GCP_FREED_KB + HW_FREED_KB + AZ_FREED_KB))
log "检查 $TARGET：GCP=$GCP_STATUS 华为云=$HW_STATUS Azure=$AZ_STATUS（完成 $ok_count/3）"

status_word() {
  case "$1" in
    ok) echo "完成" ;;
    degraded) echo "降级完成" ;;
    interrupted) echo "中断" ;;
    notrun) echo "未运行" ;;
    *) echo "无法检查" ;;
  esac
}
status_icon() {
  case "$1" in
    ok) echo "✅" ;;
    degraded|interrupted|notrun) echo "⚠️" ;;
    *) echo "❌" ;;
  esac
}

body="$(status_icon "$GCP_STATUS") **GCP**：$(status_word "$GCP_STATUS")，$GCP_DETAIL
$(status_icon "$HW_STATUS") **华为云**：$(status_word "$HW_STATUS")，$HW_DETAIL
$(status_icon "$AZ_STATUS") **Azure**：$(status_word "$AZ_STATUS")，$AZ_DETAIL"

panel_lines="**GCP 状态文件**：${GCP_EVIDENCE:-（无）}
**华为云日志**：
${HW_EVIDENCE:-（无）}
**Azure 日志**：
${AZ_EVIDENCE:-（无）}"

if [ "$ok_count" -eq 3 ]; then tpl="green"; tag="全部完成"; else tpl="red"; tag="需查看"; fi
panel_expanded="false"
[ "$ok_count" -lt 3 ] && panel_expanded="true"

# --- 发卡（带折叠面板，照 briefing.sh 的做法手拼 elements；失败兜底 feishu_card）---
elements=""
add_md() {
  local c
  c="$(json_escape "$1")"
  [ -n "$elements" ] && elements="${elements},"
  elements="${elements}{\"tag\":\"markdown\",\"content\":\"$c\"}"
}
add_raw() {
  [ -n "$elements" ] && elements="${elements},"
  elements="${elements}$1"
}
add_hr() {
  [ -n "$elements" ] && elements="${elements},"
  elements="${elements}{\"tag\":\"hr\"}"
}

add_md "$body"
add_hr
add_raw "$(metric_block "完成" "$ok_count/3" "释放空间" "$(fmt_kb "$total_kb")")"
add_raw "$(panel_json "清理详情" "$panel_lines" "$panel_expanded")"
add_md "<font color='grey'>每月 16 号 05:00 UTC 检查 · 小兔云监控</font>"

sent=0
resp="$(curl -s -m 30 --connect-timeout 10 -X POST "$FEISHU_URL" \
  -H 'Content-Type: application/json' \
  -d "{\"msg_type\":\"interactive\",\"card\":{\"schema\":\"2.0\",\"header\":{\"template\":\"$tpl\",\"title\":{\"tag\":\"plain_text\",\"content\":\"每月清理结果\"},\"subtitle\":{\"tag\":\"plain_text\",\"content\":\"检查 $TARGET\"},\"text_tag_list\":[{\"tag\":\"text_tag\",\"text\":{\"tag\":\"plain_text\",\"content\":\"$tag\"},\"color\":\"$tpl\"}]},\"body\":{\"vertical_spacing\":\"16px\",\"padding\":\"16px 20px\",\"elements\":[$elements]}}}" 2>/dev/null)"
if printf '%s' "$resp" | grep -q '"code": *0'; then
  sent=1
elif feishu_card "$tpl" "每月清理结果" "检查 $TARGET" "$body" "每月 16 号 05:00 UTC 检查 · 小兔云监控" "$tag" "$(metric_block "完成" "$ok_count/3" "释放空间" "$(fmt_kb "$total_kb")")"; then
  sent=1
fi

if [ "$sent" = "1" ]; then
  log "清理结果卡已发（完成 $ok_count/3）"
  # 全部确定才写已发标记；有未确定项时不写，方便手动重跑
  if [ "$GCP_STATUS" != "unknown" ] && [ "$HW_STATUS" != "unknown" ] && [ "$AZ_STATUS" != "unknown" ]; then
    printf '%s' "$TARGET" > "$SENT"
  else
    log "有未确定项，未写已发标记（可手动重跑）"
  fi
else
  log "清理结果卡发送失败"
fi
