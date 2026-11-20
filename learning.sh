#!/bin/bash
# 学习消息（小兔云，/root/learning.sh）
# 发往日报机器人（炭火鸽）：标题含“日报”（鸽的自定义关键词）
# 每天 08:05（北京时间）拉取 test.hqyyk.de5.net/learning.json，用飞书卡片发学习消息。
# JSON 由 Muse 每日 07:55 生成并推 GitHub（Cloudflare Pages 自动部署）。
# JSON 过期/拉不到/学习为空时静默跳过（只记日志），不发卡。
# shellcheck disable=SC1091
. /root/monitor_common.sh
URL="https://test.hqyyk.de5.net/learning.json"
LOG=/root/learning.log
log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; tail -n 300 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; }

# 清理标题里的 markdown 破坏字符
sanitize() { printf '%s' "$1" | tr -d '[]|' | tr -s ' \t' ' ' | sed 's/^ *//;s/ *$//'; }
field() { # field <line> <name>：取 "name": "value" 里的 value（value 里不含引号）
  printf '%s' "$1" | grep -o "\"$2\": *\"[^\"]*\"" | head -1 | sed "s/\"$2\": *\"//;s/\"$//"
}
numfield() { # numfield <line> <name>：取 "name": 123 里的数字
  printf '%s' "$1" | grep -o "\"$2\": *[0-9]*" | head -1 | sed "s/\"$2\": *//"
}

today=$(TZ=Asia/Shanghai date +%F)
json=""
for i in 1 2 3; do
  json=$(curl -fsSL --max-time 30 "$URL" 2>/dev/null) && [ -n "$json" ] && break
  sleep 10
done
[ -n "$json" ] || { log "拉取 learning.json 失败（3 次），跳过"; exit 0; }
jdate=$(printf '%s' "$json" | grep -o '"date": *"[^"]*"' | head -1 | sed 's/"date": *"//;s/"$//')
[ "$jdate" = "$today" ] || { log "learning.json 过期（date=$jdate，今天 $today），跳过"; exit 0; }

body=""
count=0
while IFS= read -r line; do
  case "$line" in *'"kind":'*)
    title=$(sanitize "$(field "$line" title)")
    source=$(field "$line" source)
    url=$(field "$line" url)
    [ -n "$title" ] && [ -n "$url" ] || continue
    body="$body
• [$title]($url) — $source"
    count=$((count+1))
    ;;
  esac
done <<EOF
$json
EOF
[ "$count" -gt 0 ] || { log "learning 为空，跳过"; exit 0; }
body="**推荐学习精华**$body"

# 主线提醒
mline=$(printf '%s' "$json" | grep '"mainline":')
watched=$(numfield "$mline" watched); total=$(numfield "$mline" total)
intake=$(numfield "$mline" intake_pending)
nt=$(sanitize "$(field "$mline" next_title)")
nu=$(field "$mline" next_url)
nm=$(field "$mline" next_module)
nd=$(field "$mline" next_duration)
body="$body

**主线提醒**
主线进度：$watched/$total 已看；收进区 $intake 条未学。"
if [ -n "$nt" ] && [ -n "$nu" ]; then
  body="$body
下一条：$nm [$nt]($nu)（$nd）"
fi

# 今日羊毛
deals=""
dcount=0
while IFS= read -r line; do
  case "$line" in *'"type":'*)
    title=$(sanitize "$(field "$line" title)")
    offer=$(sanitize "$(field "$line" offer)")
    url=$(field "$line" url)
    [ -n "$title" ] && [ -n "$url" ] || continue
    deals="$deals
• [$title]($url) — $offer"
    dcount=$((dcount+1))
    ;;
  esac
done <<EOF
$json
EOF
if [ "$dcount" -gt 0 ]; then
  body="$body

**今日羊毛**$deals"
fi

feishu_card_daily purple "今日学习消息 · 日报" "$today" "$body" "" "学习" "$(metric_block 推荐学习 "$count 条")"
log "学习消息已发（学习 $count 条，羊毛 $dcount 条）"
