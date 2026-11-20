#!/bin/bash
# 每日早间简报 v4.4：v4.3 + 摘要写全不截断（200 字以上才截）
# 发往日报机器人（炭火鸽）：主卡直接 POST 到 FEISHU_URL_DAILY，兜底走 feishu_card_daily
# 标题含“日报”（鸽的自定义关键词）；告警类脚本仍走炭火鸡，不动
# 布局：⭐ 今日重点（蓝底高亮块，前沿动态）→ 新闻分区（DeepMind / 论文 / HN / 少数派 /
# LINUX DO，按用户定位筛选）→ hr → 指标块（服务器/磁盘）→ 服务器详情折叠面板
# （四台 + 域名×2 + InstaBox + 小兔云，异常时默认展开）→ 到期 → 预算（无底部灰色备注）
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/monitor_common.sh"
# 强制 UTF-8 locale，保证 ${s:0:20} 按字符（不是字节）截取中文摘要
export LC_ALL=C.UTF-8

NL=$'\n'

# 定位关键词（全小写；匹配时标题先转小写）：只推与用户定位相关的新闻，不推大众内容
KW_CN='大模型|llm|gpt|claude|gemini|deepseek|grok|qwen|llama|ai|人工智能|多模态|算力|gpu|推理|微调|rag|agent|智能体|开源|vps|服务器|免费|部署|模型|提示词|cursor|copilot|免费节点|节点订阅|住宅ip|vless|vmess'
KW_EN='openai|anthropic|llm|gpt|claude|gemini|deepseek|grok|qwen|llama|model|gpu|multimodal|agent|rag|fine-tun|open source|server|free|inference|transformer|neural|deep learning|vless|vmess|residential|(^|[^a-z])ai([^a-z]|$)'
# 排除关键词：用户已过的阶段（论文已投，不再推 AI 写论文类）+ 与学习无关的内容
# 注意：中文标题里 AI 前后常有空格（“用 AI 写”），模式里用 ? 容忍空格
EXCLUDE_CN='ai ?写|ai ?辅助 ?写作|ai ?写作|ai ?辅助.*(完成|写|写作).*(综述|论文)|论文写作|投稿指南|毕业论文|考研|考公|游戏|影视|娱乐|追星|八卦'
EXCLUDE_EN='essay writing|thesis writing|gaming|celebrity|gossip'
# 前沿关键词：用于挑今日重点（新模型发布/突破/纪录类优先）
CALL_OUT_CN='发布|新模型|突破|刷新纪录|sota|benchmark|重大更新|开源发布|gemini|gpt-5|opus|sonnet|deepseek|grok|deepmind|openai|anthropic'
CALL_OUT_EN='releas|breakthrough|record|sota|benchmark|launch|announc|introduc|gemini|gpt-5|opus|sonnet|deepseek|grok|deepmind|openai|anthropic'

days_left() {
  local target_s now_s
  target_s="$(date -u -d "$1" +%s 2>/dev/null)" || { echo "?"; return; }
  now_s="$(date -u +%s)"
  echo $(( (target_s - now_s) / 86400 ))
}

# JSON 里常见的 \uXXXX 转义还原（只处理常见的几个）
json_unescape() {
  sed -e 's/\\u0026/\&/g' -e 's/\\u003c/</g' -e 's/\\u003e/>/g' -e "s/\\u0027/'/g" -e 's/\\u0022/"/g' -e 's/\\u2014/-/g' -e 's/\\u3002/./g'
}

# 标题清洗：去掉 | [ ]（| 是标题与链接的分隔符，[ ] 会破坏链接语法），去首尾空格
clean_title() {
  sed -e 's/|//g' -e 's/\[//g' -e 's/\]//g' -e 's/^ *//' -e 's/ *$//'
}

# 摘要清洗：去掉 HTML 标签与实体、折叠空白；写全不截断（200 字以上才截，英文遇词界回退不断词）
# 输出空表示无可用摘要（调用方渲染为纯标题行）；截断时末尾加 …
short_summary() {
  local s="$1" t bt limit=200
  s="$(printf '%s' "$1" | sed -e 's/<[^>]*>//g' -e 's/&nbsp;/ /g' -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e "s/&#39;/'/g" -e 's/&amp;/\&/g' -e 's/|//g' -e 's/\[//g' -e 's/\]//g' -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ *//' -e 's/ *$//')"
  [ -z "$s" ] && return 1
  if [ "${#s}" -le "$limit" ]; then
    printf '%s' "$s"
    return 0
  fi
  t="${s:0:limit}"
  # 英文截到词中间时回退到最后一个空格（回退后太短则不回退）
  if [ "${s:limit:1}" != " " ] && [ "${t: -1}" != " " ] && [[ "$t" == *" "* ]]; then
    bt="${t% *}"
    [ "${#bt}" -ge $((limit - 10)) ] && t="$bt"
  fi
  t="$(printf '%s' "$t" | sed -e 's/[ ,，、；：:;.!?。]*$//')"
  printf '%s…' "$t"
}

# 取文章页摘要：抓 meta description（无则 og:description），失败或无描述返回 1
fetch_desc() {
  local url="$1" html desc
  [ -z "$url" ] && return 1
  html="$(curl -sL --compressed --max-time 8 "$url" 2>/dev/null | tr '\n' ' ')"
  [ -z "$html" ] && return 1
  desc="$(printf '%s' "$html" | grep -oi '<meta[^>]*name="description"[^>]*>' | head -n 1 | grep -oi 'content="[^"]*"' | head -n 1 | sed -e 's/^content="//i' -e 's/"$//')"
  if [ -z "$desc" ]; then
    desc="$(printf '%s' "$html" | grep -oi '<meta[^>]*property="og:description"[^>]*>' | head -n 1 | grep -oi 'content="[^"]*"' | head -n 1 | sed -e 's/^content="//i' -e 's/"$//')"
  fi
  [ -z "$desc" ] && return 1
  short_summary "$desc"
}

# 取 LINUX DO「标题|链接|摘要」（RSS 取 15 条，按定位筛选，取 3 条；失败返回 1）
# RSS 被挡时回退到 latest.json（只有标题，无链接无摘要）
fetch_linuxdo() {
  local rss titles links pairs raw
  rss="$(curl -s --compressed --max-time 12 "https://linux.do/latest.rss" 2>/dev/null)"
  if [ -n "$rss" ]; then
    titles="$(printf '%s' "$rss" | grep -o '<title>[^<]*</title>' | tail -n +2 \
      | sed -e 's/^<title>//' -e 's/<\/title>$//' -e 's/<!\[CDATA\[//g' -e 's/\]\]>//g' \
        -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e "s/&#39;/'/g" -e 's/&amp;/\&/g' \
      | clean_title | head -n 15)"
    links="$(printf '%s' "$rss" | grep -o '<link>[^<]*</link>' | tail -n +2 \
      | sed -e 's/^<link>//' -e 's/<\/link>$//' | head -n 15)"
    if [ -n "$titles" ]; then
      pairs="$(paste -d'|' <(printf '%s\n' "$titles") <(printf '%s\n' "$links") \
        | awk -F'|' -v pat="$KW_CN" -v ex="$EXCLUDE_CN" 'tolower($1) ~ pat && tolower($1) !~ ex' | head -n 3)"
      if [ -n "$pairs" ]; then
        while IFS='|' read -r t link; do
          [ -z "$t" ] && continue
          printf '%s|%s|%s\n' "$t" "$link" "$(fetch_desc "$link")"
        done <<EOF
$pairs
EOF
      fi
      return 0
    fi
  fi
  # 回退：latest.json 只有标题
  raw="$(curl -s --compressed --max-time 12 "https://linux.do/latest.json" 2>/dev/null)"
  [ -z "$raw" ] && return 1
  titles="$(printf '%s' "$raw" | grep -o '"title":"[^"]*"' \
    | sed -e 's/^"title":"//' -e 's/"$//' \
    | json_unescape \
    | clean_title \
    | awk -v pat="$KW_CN" -v ex="$EXCLUDE_CN" 'tolower($0) ~ pat && tolower($0) !~ ex' \
    | head -n 3)"
  [ -n "$titles" ] && printf '%s\n' "$titles"
  return 0
}

# 取少数派「标题|链接」（RSS 取 15 条，按定位筛选，取 3 条；失败返回 1）
# 注：V2EX 的标题是 \uXXXX 转义，纯 Bash 解不出来，已弃用
fetch_sspai() {
  local rss titles links pairs
  rss="$(curl -s --compressed --max-time 12 "https://sspai.com/feed" 2>/dev/null)"
  [ -z "$rss" ] && return 1
  titles="$(printf '%s' "$rss" | grep -o '<title>[^<]*</title>' | tail -n +2 \
    | sed -e 's/^<title>//' -e 's/<\/title>$//' -e 's/<!\[CDATA\[//g' -e 's/\]\]>//g' \
      -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e "s/&#39;/'/g" -e 's/&amp;/\&/g' \
    | clean_title | head -n 15)"
  links="$(printf '%s' "$rss" | grep -o '<link>[^<]*</link>' | tail -n +2 \
    | sed -e 's/^<link>//' -e 's/<\/link>$//' | head -n 15)"
  [ -z "$titles" ] && return 1
  pairs="$(paste -d'|' <(printf '%s\n' "$titles") <(printf '%s\n' "$links") \
    | awk -F'|' -v pat="$KW_CN" -v ex="$EXCLUDE_CN" 'tolower($1) ~ pat && tolower($1) !~ ex' | head -n 3)"
  [ -z "$pairs" ] && return 0
  while IFS='|' read -r t link; do
    [ -z "$t" ] && continue
    printf '%s|%s|%s\n' "$t" "$link" "$(fetch_desc "$link")"
  done <<EOF
$pairs
EOF
  return 0
}

# 取 Hacker News「标题|链接|摘要」（取 8 条，按定位筛选，取 3 条；失败返回 1）
# 摘要优先抓外链文章页 meta description；无外链（Ask HN 等）时用帖子正文开头
fetch_hn() {
  local ids id json title ext_url text pairs="" sel summary
  ids="$(curl -s --compressed --max-time 12 "https://hacker-news.firebaseio.com/v0/topstories.json" 2>/dev/null | tr -d '[]' | tr ',' '\n' | head -n 8)"
  [ -z "$ids" ] && return 1
  for id in $ids; do
    json="$(curl -s --compressed --max-time 5 "https://hacker-news.firebaseio.com/v0/item/${id}.json" 2>/dev/null)"
    [ -z "$json" ] && continue
    title="$(printf '%s' "$json" | grep -o '"title":"[^"]*"' | head -n 1 | sed -e 's/^"title":"//' -e 's/"$//' | json_unescape | clean_title)"
    [ -z "$title" ] && continue
    ext_url="$(printf '%s' "$json" | grep -o '"url":"[^"]*"' | head -n 1 | sed -e 's/^"url":"//' -e 's/"$//')"
    text="$(printf '%s' "$json" | grep -o '"text":"[^"]*"' | head -n 1 | sed -e 's/^"text":"//' -e 's/"$//' -e 's/|//g' | json_unescape)"
    pairs="${pairs}${title}|https://news.ycombinator.com/item?id=${id}|${ext_url}|${text}${NL}"
  done
  [ -z "$pairs" ] && return 1
  sel="$(printf '%s' "$pairs" | awk -F'|' -v pat="$KW_EN" -v ex="$EXCLUDE_EN" 'tolower($1) ~ pat && tolower($1) !~ ex' | head -n 3)"
  [ -z "$sel" ] && return 0
  while IFS='|' read -r t link ext_url text; do
    [ -z "$t" ] && continue
    summary=""
    if [ -n "$ext_url" ]; then
      summary="$(fetch_desc "$ext_url")"
    fi
    if [ -z "$summary" ] && [ -n "$text" ]; then
      summary="$(short_summary "$text")"
    fi
    printf '%s|%s|%s\n' "$t" "$link" "$summary"
  done <<EOF
$sel
EOF
  return 0
}

# 取 Google DeepMind 博客「标题|链接」（RSS 取 10 条，按定位筛选，取 3 条；失败返回 1）
# 前沿来源：Gemini 等新模型成就主要从这里来
fetch_deepmind() {
  local rss titles links pairs
  rss="$(curl -sL --compressed --max-time 15 "https://deepmind.google/blog/rss.xml" 2>/dev/null)"
  [ -z "$rss" ] && return 1
  titles="$(printf '%s' "$rss" | grep -o '<title>[^<]*</title>' | tail -n +2 \
    | sed -e 's/^<title>//' -e 's/<\/title>$//' -e 's/<!\[CDATA\[//g' -e 's/\]\]>//g' \
      -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e "s/&#39;/'/g" -e 's/&amp;/\&/g' \
    | clean_title | head -n 10)"
  links="$(printf '%s' "$rss" | grep -o '<link>[^<]*</link>' | tail -n +2 \
    | sed -e 's/^<link>//' -e 's/<\/link>$//' | head -n 10)"
  [ -z "$titles" ] && return 1
  pairs="$(paste -d'|' <(printf '%s\n' "$titles") <(printf '%s\n' "$links") \
    | awk -F'|' -v pat="$KW_EN" -v ex="$EXCLUDE_EN" 'tolower($1) ~ pat && tolower($1) !~ ex' | head -n 3)"
  [ -z "$pairs" ] && return 0
  while IFS='|' read -r t link; do
    [ -z "$t" ] && continue
    printf '%s|%s|%s\n' "$t" "$link" "$(fetch_desc "$link")"
  done <<EOF
$pairs
EOF
  return 0
}

# 取 arXiv 多模态最新论文「标题|链接」（取 2 篇；查询本身就是筛选，不再过滤；失败返回 1）
fetch_arxiv() {
  local resp ids titles pairs
  resp="$(curl -s --compressed --max-time 20 "https://export.arxiv.org/api/query?search_query=all:multimodal+AND+%28cat:cs.CV+OR+cat:cs.AI+OR+cat:cs.CL+OR+cat:cs.LG%29&start=0&max_results=5&sortBy=submittedDate&sortOrder=descending" 2>/dev/null)"
  [ -z "$resp" ] && return 1
  ids="$(printf '%s' "$resp" | grep -o '<id>http://arxiv.org/abs/[^<]*</id>' | sed -e 's/^<id>//' -e 's/<\/id>$//' | head -n 5)"
  titles="$(printf '%s' "$resp" | grep -o '<title>[^<]*</title>' | tail -n +2 \
    | sed -e 's/^<title>//' -e 's/<\/title>$//' | clean_title | head -n 5)"
  [ -z "$titles" ] && return 1
  pairs="$(paste -d'|' <(printf '%s\n' "$titles") <(printf '%s\n' "$ids") | head -n 2)"
  [ -z "$pairs" ] && return 0
  while IFS='|' read -r t link; do
    [ -z "$t" ] && continue
    printf '%s|%s|%s\n' "$t" "$link" "$(fetch_desc "$link")"
  done <<EOF
$pairs
EOF
  return 0
}

# --- 新闻（按来源分区；抓取失败则该区不出现，筛选后无匹配则显示“今日暂无相关内容”） ---
dm_raw="$(fetch_deepmind)"; dm_rc=$?
dm_lines=""
if [ "$dm_rc" = "0" ]; then
  while IFS='|' read -r t link summary; do
    [ -z "$t" ] && continue
    if [ -n "$link" ]; then
      if [ -n "$summary" ]; then
        dm_lines="${dm_lines}• [${t}](${link}) — ${summary}${NL}"
      else
        dm_lines="${dm_lines}• [${t}](${link})${NL}"
      fi
    else
      dm_lines="${dm_lines}• ${t}${NL}"
    fi
  done <<EOF
$dm_raw
EOF
  [ -z "$dm_lines" ] && dm_lines="今日暂无相关内容"
fi

ax_raw="$(fetch_arxiv)"; ax_rc=$?
ax_lines=""
if [ "$ax_rc" = "0" ]; then
  while IFS='|' read -r t link summary; do
    [ -z "$t" ] && continue
    if [ -n "$link" ]; then
      if [ -n "$summary" ]; then
        ax_lines="${ax_lines}• [${t}](${link}) — ${summary}${NL}"
      else
        ax_lines="${ax_lines}• [${t}](${link})${NL}"
      fi
    else
      ax_lines="${ax_lines}• ${t}${NL}"
    fi
  done <<EOF
$ax_raw
EOF
  [ -z "$ax_lines" ] && ax_lines="今日暂无相关内容"
fi

do_raw="$(fetch_linuxdo)"; do_rc=$?
do_lines=""
if [ "$do_rc" = "0" ]; then
  while IFS='|' read -r t link summary; do
    [ -z "$t" ] && continue
    if [ -n "$link" ]; then
      if [ -n "$summary" ]; then
        do_lines="${do_lines}• [${t}](${link}) — ${summary}${NL}"
      else
        do_lines="${do_lines}• [${t}](${link})${NL}"
      fi
    else
      do_lines="${do_lines}• ${t}${NL}"
    fi
  done <<EOF
$do_raw
EOF
  [ -z "$do_lines" ] && do_lines="今日暂无相关内容"
fi

sspai_raw="$(fetch_sspai)"; sspai_rc=$?
sspai_lines=""
if [ "$sspai_rc" = "0" ]; then
  while IFS='|' read -r t link summary; do
    [ -z "$t" ] && continue
    if [ -n "$link" ]; then
      if [ -n "$summary" ]; then
        sspai_lines="${sspai_lines}• [${t}](${link}) — ${summary}${NL}"
      else
        sspai_lines="${sspai_lines}• [${t}](${link})${NL}"
      fi
    else
      sspai_lines="${sspai_lines}• ${t}${NL}"
    fi
  done <<EOF
$sspai_raw
EOF
  [ -z "$sspai_lines" ] && sspai_lines="今日暂无相关内容"
fi

hn_raw="$(fetch_hn)"; hn_rc=$?
hn_lines=""
if [ "$hn_rc" = "0" ]; then
  while IFS='|' read -r t link summary; do
    [ -z "$t" ] && continue
    if [ -n "$link" ]; then
      if [ -n "$summary" ]; then
        hn_lines="${hn_lines}• [${t}](${link}) — ${summary}${NL}"
      else
        hn_lines="${hn_lines}• [${t}](${link})${NL}"
      fi
    else
      hn_lines="${hn_lines}• ${t}${NL}"
    fi
  done <<EOF
$hn_raw
EOF
  [ -z "$hn_lines" ] && hn_lines="今日暂无相关内容"
fi

# --- 今日重点：从各区新闻里挑第一条前沿动态（DeepMind → HN → 少数派 → LINUX DO） ---
callout=""
for src in "$dm_lines" "$hn_lines" "$sspai_lines" "$do_lines"; do
  [ -n "$callout" ] && break
  [ "$src" = "今日暂无相关内容" ] && continue
  pick="$(printf '%s' "$src" | grep -iE "$CALL_OUT_CN|$CALL_OUT_EN" | head -n 1 | sed 's/^• //')"
  [ -n "$pick" ] && callout="$pick"
done

# --- 服务器快检 ---

# --- 新闻存档：把今天简报的新闻标题+链接存到 /root/briefing-news/，供之后查摘要 ---
NEWS_DIR="/root/briefing-news"
mkdir -p "$NEWS_DIR"
news_date="$(today_cn)"
news_file="$NEWS_DIR/${news_date}.txt"
{
  echo "=== 早间简报 ${news_date} ==="
  echo "[今日重点] ${callout:-无}"
  echo "[DeepMind rc=${dm_rc}]"
  [ -n "$dm_raw" ] && printf '%s\n' "$dm_raw"
  echo "[论文 rc=${ax_rc}]"
  [ -n "$ax_raw" ] && printf '%s\n' "$ax_raw"
  echo "[Hacker News rc=${hn_rc}]"
  [ -n "$hn_raw" ] && printf '%s\n' "$hn_raw"
  echo "[少数派 rc=${sspai_rc}]"
  [ -n "$sspai_raw" ] && printf '%s\n' "$sspai_raw"
  echo "[LINUX DO rc=${do_rc}]"
  [ -n "$do_raw" ] && printf '%s\n' "$do_raw"
} > "$news_file"
find "$NEWS_DIR" -name '2*.txt' -type f -mtime +7 -delete 2>/dev/null

gcp="DOWN"; check_tcp 136.86.244.77 8443 && gcp="UP"
hw="DOWN"; check_tcp 111.91.16.60 22 && hw="UP"
az="DOWN"; check_tcp 13.78.14.46 22 && az="UP"
cl="DOWN"; check_http "https://proxy-hqaeqnei-workspace-r6y0xr.cloady.io/" && cl="UP"
hq="DOWN"; check_http "https://hqyyk.loc.cc/" && hq="UP"
hqt="DOWN"; check_http "https://test.hqyyk.de5.net/" && hqt="UP"

up_count=0
[ "$gcp" = "UP" ] && up_count=$((up_count + 1))
[ "$hw" = "UP" ] && up_count=$((up_count + 1))
[ "$az" = "UP" ] && up_count=$((up_count + 1))
[ "$cl" = "UP" ] && up_count=$((up_count + 1))
[ "$hq" = "UP" ] && up_count=$((up_count + 1))
[ "$hqt" = "UP" ] && up_count=$((up_count + 1))

disk_used="$(df / | awk 'NR==2 {print $5}')"
mem_avail="$(free -m | awk '/^Mem:/ {print $7}')"

# --- InstaBox 状态（保活脚本每 20 分钟更新 /root/instabox/status）---
ib_line=""
if [ -f /root/instabox/status ]; then
  ib_state="$(cut -d'|' -f1 /root/instabox/status)"
  ib_maxrun="$(cut -d'|' -f2 /root/instabox/status)"
  ib_runstarted="$(cut -d'|' -f3 /root/instabox/status)"
  ib_checked="$(cut -d'|' -f5 /root/instabox/status)"
  ib_age=""
  if [ -n "$ib_runstarted" ] && [ "$ib_runstarted" != "null" ]; then
    ib_start="$(date -u -d "$ib_runstarted" +%s 2>/dev/null)"
    [ -n "$ib_start" ] && ib_age=$(( ( $(date -u +%s) - ib_start ) / 60 ))
  fi
  ib_stale=1
  [ -n "$ib_checked" ] && [ $(( $(date -u +%s) - ib_checked )) -lt 3600 ] && ib_stale=0
  if [ "$ib_stale" = "1" ]; then
    ib_line="**InstaBox** ❓ 状态未知（保活未更新）"
  elif [ "$ib_state" = "running" ]; then
    ib_line="**InstaBox** 🟢 运行中（本段 ${ib_age:-?}/${ib_maxrun:-?} 分钟）"
  elif [ "$ib_state" = "suspended" ]; then
    ib_line="**InstaBox** ⏸️ 已暂停"
  elif [ "$ib_state" = "stopped" ]; then
    ib_line="**InstaBox** ⏹️ 已停止"
  else
    ib_line="**InstaBox** ${ib_state:-未知}"
  fi
fi

# --- 服务器详情（折叠面板内容：四台服务器 + 域名（主页/落地页）+ InstaBox + 小兔云本机） ---
panel_lines=""
[ "$gcp" = "UP" ] && panel_lines="**GCP** ✅ 正常" || panel_lines="**GCP** ❌ 异常"
[ "$hw" = "UP" ] && panel_lines="${panel_lines}${NL}**华为云新加坡** ✅ 正常" || panel_lines="${panel_lines}${NL}**华为云新加坡** ❌ 异常"
[ "$az" = "UP" ] && panel_lines="${panel_lines}${NL}**Azure 日本** ✅ 正常" || panel_lines="${panel_lines}${NL}**Azure 日本** ❌ 异常"
[ "$cl" = "UP" ] && panel_lines="${panel_lines}${NL}**cloady proxy（德国）** ✅ 正常" || panel_lines="${panel_lines}${NL}**cloady proxy（德国）** ❌ 异常"
[ "$hq" = "UP" ] && panel_lines="${panel_lines}${NL}**hqyyk.loc.cc 主页** ✅ 正常" || panel_lines="${panel_lines}${NL}**hqyyk.loc.cc 主页** ❌ 异常"
[ "$hqt" = "UP" ] && panel_lines="${panel_lines}${NL}**test.hqyyk.de5.net 落地页** ✅ 正常" || panel_lines="${panel_lines}${NL}**test.hqyyk.de5.net 落地页** ❌ 异常"
[ -n "$ib_line" ] && panel_lines="${panel_lines}${NL}${ib_line}"
panel_lines="${panel_lines}${NL}**小兔云** 💾 磁盘 ${disk_used:-?} · 内存可用 ${mem_avail:-?}MB"

panel_expanded="false"
[ "$up_count" -lt 6 ] && panel_expanded="true"
panel="$(panel_json "🖥️ 服务器详情（${up_count}/6 正常）" "$panel_lines" "$panel_expanded")"

metric="$(metric_block "服务器" "${up_count}/6 正常" "小兔云磁盘" "${disk_used:-?}")"

# --- 拼卡片 elements ---
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

# 今日重点（有前沿动态时才出现）
if [ -n "$callout" ]; then
  add_raw "$(callout_block "⭐ 今日重点" "$callout")"
fi

# 新闻分区（抓取失败的区不出现；全部失败时显示获取失败）
if [ "$dm_rc" = "0" ]; then
  add_md "🧠 **Google DeepMind · 前沿**"
  add_md "$dm_lines"
fi
if [ "$ax_rc" = "0" ]; then
  add_md "📄 **论文 · 多模态**"
  add_md "$ax_lines"
fi
if [ "$hn_rc" = "0" ]; then
  add_md "🌐 **Hacker News · 英文科技**"
  add_md "$hn_lines"
fi
if [ "$sspai_rc" = "0" ]; then
  add_md "📰 **少数派**"
  add_md "$sspai_lines"
fi
if [ "$do_rc" = "0" ]; then
  add_md "💬 **LINUX DO**"
  add_md "$do_lines"
fi
if [ "$dm_rc" != "0" ] && [ "$ax_rc" != "0" ] && [ "$hn_rc" != "0" ] && [ "$sspai_rc" != "0" ] && [ "$do_rc" != "0" ]; then
  add_md "📰 **今日新闻**"
  add_md "（新闻获取失败）"
fi

add_hr
add_raw "$metric"
add_raw "$panel"
add_md "⏰ **到期**：小兔云 $(days_left 2026-12-04) 天 · GCP $(days_left 2027-02-01) 天 · Azure $(days_left 2027-10-18) 天 · 华为云 $(days_left 2027-06-15) 天"

# --- 预算（azure-budget.sh 每天 07:30 写状态文件；没有新鲜状态时显示静态行）---
budget_md="💰 **预算**：Azure \$10/月（邮件提醒，飞书接入待部署）"
if [ -f /root/azure-budget/status ]; then
  b_spend="$(cut -d'|' -f1 /root/azure-budget/status)"
  b_cur="$(cut -d'|' -f2 /root/azure-budget/status)"
  b_pct="$(cut -d'|' -f3 /root/azure-budget/status)"
  b_checked="$(cut -d'|' -f4 /root/azure-budget/status)"
  if [ -n "$b_checked" ] && [ $(( $(date -u +%s) - b_checked )) -lt 90000 ]; then
    budget_md="💰 **预算**：Azure 本月已用 ${b_spend} ${b_cur}（${b_pct}% / \$10）"
  fi
fi
add_md "$budget_md"

# 副标题带星期：2026-11-16 星期一
wd_num="$(date -u -d '+8 hours' +%u)"
case "$wd_num" in
  1) wd="一";; 2) wd="二";; 3) wd="三";; 4) wd="四";; 5) wd="五";; 6) wd="六";; 7) wd="日";; *) wd="" ;;
esac
subtitle="$(today_cn) 星期${wd}"
s="$(json_escape "$subtitle")"

resp="$(curl -s -m 30 --connect-timeout 10 -X POST "$FEISHU_URL_DAILY" \
  -H 'Content-Type: application/json' \
  -d "{\"msg_type\":\"interactive\",\"card\":{\"schema\":\"2.0\",\"header\":{\"template\":\"purple\",\"title\":{\"tag\":\"plain_text\",\"content\":\"早间简报 · 日报\"},\"subtitle\":{\"tag\":\"plain_text\",\"content\":\"$s\"},\"text_tag_list\":[{\"tag\":\"text_tag\",\"text\":{\"tag\":\"plain_text\",\"content\":\"日报\"},\"color\":\"purple\"}]},\"body\":{\"vertical_spacing\":\"16px\",\"padding\":\"16px 20px\",\"elements\":[$elements]}}}" 2>/dev/null)"

if printf '%s' "$resp" | grep -q '"code": *0'; then
  echo "[$(now_cn)] briefing sent" >> /root/briefing.log
else
  # 新版卡片失败，兜底旧版单块卡片（feishu_card 自带极简卡 + 纯文本兜底）
  fallback_body="📰 **新闻**${NL}${dm_lines}${ax_lines}${do_lines}${sspai_lines}${hn_lines}🖥️ **服务器：${up_count}/6 正常**${NL}💾 小兔云：磁盘 ${disk_used:-?} · 内存可用 ${mem_avail:-?}MB${NL}⏰ 到期：小兔云 $(days_left 2026-12-04)天 · GCP $(days_left 2027-02-01)天 · Azure $(days_left 2027-10-18)天 · 华为云 $(days_left 2027-06-15)天"
  if feishu_card_daily purple "早间简报 · 日报" "$(today_cn)" "$fallback_body" "小兔云监控 · 每天 08:00" "日报" "$(metric_block "服务器" "${up_count}/6 正常" "小兔云磁盘" "${disk_used:-?}")"; then
    echo "[$(now_cn)] briefing sent (fallback card)" >> /root/briefing.log
  else
    echo "[$(now_cn)] briefing send FAILED" >> /root/briefing.log
  fi
fi
