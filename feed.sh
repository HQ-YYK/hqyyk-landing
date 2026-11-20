#!/bin/bash
# Feed 摘要（小兔云，/root/feed.sh）
# 发往日报机器人（炭火鸽）：标题含“日报”（鸽的自定义关键词）
# 每天 08:10（北京时间）拉取 test.hqyyk.de5.net/feed.json，用飞书卡片发 Feed 摘要。
# JSON 由 Muse 每日 08:00 生成并推 GitHub（Cloudflare Pages 自动部署）。
# JSON 过期/拉不到/无新文章时静默跳过（只记日志），不发卡。
# 已发过的文章按 unit_id 记在 /root/feed-delivered.txt，去重。
# shellcheck disable=SC1091
. /root/monitor_common.sh
URL="https://test.hqyyk.de5.net/feed.json"
LOG=/root/feed.log
DELIVERED=/root/feed-delivered.txt
log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; tail -n 300 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; }

# 清理标题里的 markdown 破坏字符
sanitize() { printf '%s' "$1" | tr -d '[]|' | tr -s ' \t' ' ' | sed 's/^ *//;s/ *$//'; }
field() { # field <line> <name>：取 "name": "value" 里的 value（value 里不含引号）
  printf '%s' "$1" | grep -o "\"$2\": *\"[^\"]*\"" | head -1 | sed "s/\"$2\": *\"//;s/\"$//"
}

today=$(TZ=Asia/Shanghai date +%F)
json=""
for i in 1 2 3; do
  json=$(curl -fsSL --max-time 30 "$URL" 2>/dev/null) && [ -n "$json" ] && break
  sleep 10
done
[ -n "$json" ] || { log "拉取 feed.json 失败（3 次），跳过"; exit 0; }
jdate=$(printf '%s' "$json" | grep -o '"date": *"[^"]*"' | head -1 | sed 's/"date": *"//;s/"$//')
[ "$jdate" = "$today" ] || { log "feed.json 过期（date=$jdate，今天 $today），跳过"; exit 0; }

touch "$DELIVERED"
body=""
count=0
newids=""
while IFS= read -r line; do
  case "$line" in *'"id":'*)
    id=$(field "$line" id)
    title=$(sanitize "$(field "$line" title)")
    category=$(field "$line" category)
    excerpt=$(sanitize "$(field "$line" excerpt)")
    url=$(field "$line" url)
    [ -n "$id" ] && [ -n "$title" ] || continue
    grep -qxF "$id" "$DELIVERED" && continue
    if [ -n "$url" ]; then
      body="$body
• **[$title]($url)** · $category
  $excerpt"
    else
      body="$body
• **$title** · $category
  $excerpt"
    fi
    newids="$newids
$id"
    count=$((count+1))
    ;;
  esac
done <<EOF
$json
EOF
[ "$count" -gt 0 ] || { log "无新文章，跳过"; exit 0; }

if feishu_card_daily purple "Feed 摘要 · 日报" "$today" "$body" "全文在 Muse App 的 Feed 标签页里看" "Feed" "$(metric_block 新文章 "$count 篇")"; then
  printf '%s\n' "$newids" | grep -v '^$' >> "$DELIVERED"
  tail -n 200 "$DELIVERED" > "$DELIVERED.tmp" && mv "$DELIVERED.tmp" "$DELIVERED"
  log "Feed 摘要已发（$count 篇）"
else
  log "Feed 摘要发送失败，IDs 未标记"
fi
