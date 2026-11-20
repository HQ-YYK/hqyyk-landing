#!/bin/bash
# 小兔云监控公共函数
# 飞书 webhook 地址在运行时从 /root/remind.sh 里提取，不写在任何文件里
# 双机器人（2026-11-20，用户定）：告警走炭火鸡（FEISHU_URL，remind.sh），
# 日报走炭火鸽（FEISHU_URL_DAILY，/root/feishu-daily-webhook.txt，一行一个地址）
# 飞书消息一律用卡片（Card JSON 2.0，feishu_card），纯文本 feishu_send 仅作兜底
# 卡片模板（用户 2026-11-16 定）：schema 2.0；不用 note / action / wide_screen_mode
# 等 v1 废弃字段；body 用 vertical_spacing + padding 拉开呼吸感；每张卡至少一个
# 灰底指标块（column_set，大数字 heading + 小灰字 notation）；次要信息进折叠面板

FEISHU_URL="$(grep -oE 'https://open\.feishu\.cn[0-9A-Za-z/_=?&%.-]+' /root/remind.sh 2>/dev/null | head -n1)"
if [ -z "$FEISHU_URL" ]; then
  FEISHU_URL="$(grep -oE 'https://open\.feishu\.cn[0-9A-Za-z/_=?&%.-]+' /root/renew_remind.sh 2>/dev/null | head -n1)"
fi

# 日报机器人（炭火鸽）webhook：只存在 /root/feishu-daily-webhook.txt（一行），
# 文件缺失时 feishu_card_daily 直接报错（看门狗查日志失败标记会告警），
# 不回落到告警机器人，避免日报混进告警流
FEISHU_URL_DAILY="$(grep -oE 'https://open\.feishu\.cn[0-9A-Za-z/_=?&%.-]+' /root/feishu-daily-webhook.txt 2>/dev/null | head -n1)"

# JSON 转义（无 python3，用 sed，与 remind.sh 同款做法）
json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'
}

# 发飞书纯文本消息到指定地址：feishu_send_to <url> "全文"（可含多行；仅作卡片发送失败时的兜底）
feishu_send_to() {
  local url="$1" text="$2" esc
  if [ -z "$url" ]; then
    echo "ERROR: feishu webhook not found" >&2
    return 1
  fi
  esc="$(json_escape "$text")"
  curl -s -m 30 --connect-timeout 10 -X POST "$url" \
    -H 'Content-Type: application/json' \
    -d "{\"msg_type\":\"text\",\"content\":{\"text\":\"${esc}\"}}" >/dev/null
}

# 发飞书纯文本消息到告警机器人（炭火鸡）：feishu_send "全文"
feishu_send() { feishu_send_to "$FEISHU_URL" "$1"; }

# 指标块：metric_block <标签1> <值1> [标签2] [值2]
# 输出一个浅灰底 column_set JSON（1-2 列），每列：小灰标签（notation）+ 大数字（heading 加粗）
# 背景用 grey-50（明确的浅灰 #f5f6f7）；column_set 和 column 上都设 background_style（双重保险）
metric_block() {
  local l1="$1" v1="$2" l2="${3:-}" v2="${4:-}"
  local c1 c2 cols
  c1="{\"tag\":\"column\",\"width\":\"weighted\",\"weight\":1,\"background_style\":\"grey-50\",\"elements\":[{\"tag\":\"markdown\",\"text_size\":\"notation\",\"content\":\"<font color='grey'>$(json_escape "$l1")</font>\"},{\"tag\":\"markdown\",\"text_size\":\"heading\",\"content\":\"**$(json_escape "$v1")**\"}]}"
  cols="$c1"
  if [ -n "$l2" ]; then
    c2="{\"tag\":\"column\",\"width\":\"weighted\",\"weight\":1,\"background_style\":\"grey-50\",\"elements\":[{\"tag\":\"markdown\",\"text_size\":\"notation\",\"content\":\"<font color='grey'>$(json_escape "$l2")</font>\"},{\"tag\":\"markdown\",\"text_size\":\"heading\",\"content\":\"**$(json_escape "$v2")**\"}]}"
    cols="$c1,$c2"
  fi
  printf '{"tag":"column_set","background_style":"grey-50","flex_mode":"stretch","columns":[%s]}' "$cols"
}

# 高亮块（callout 风格）：callout_block <标签> <内容markdown>
# 蓝底（blue-50）单列 column_set，用于突出今日最重要的一条内容
callout_block() {
  local label="$1" content="$2"
  printf '{"tag":"column_set","background_style":"blue-50","flex_mode":"stretch","columns":[{"tag":"column","width":"weighted","weight":1,"background_style":"blue-50","elements":[{"tag":"markdown","text_size":"notation","content":"<font color='"'"'grey'"'"'>%s</font>"},{"tag":"markdown","content":"%s"}]}]}' "$(json_escape "$label")" "$(json_escape "$content")"
}

# 折叠面板：panel_json <标题> <内容> [expanded:true/false，默认 false]
# 灰底、8px 圆角、标题右侧 down-small 图标（展开时旋转 180°）
# 注意：面板背景字段是 background_color（column_set 才是 background_style）
# 注意：2.0 官方文档规定 header.title 只能是 markdown 或 plain_text，elements 里用
# markdown；之前用 div+lark_md 被接口以 200621 拒收（2026-11-16 实测），不要改回 div
panel_json() {
  local title="$1" content="$2" expanded="${3:-false}"
  printf '{"tag":"collapsible_panel","expanded":%s,"background_color":"grey","header":{"title":{"tag":"markdown","content":"%s"},"vertical_align":"center","icon":{"tag":"standard_icon","token":"down-small-ccm_outlined","color":"","size":"16px 16px"},"icon_position":"right","icon_expanded_angle":-180},"border":{"color":"grey","corner_radius":"8px"},"vertical_spacing":"8px","padding":"8px 8px 8px 8px","elements":[{"tag":"markdown","content":"%s"}]}' "$expanded" "$(json_escape "$title")" "$(json_escape "$content")"
}

# 发飞书卡片消息（Card JSON 2.0）到指定地址：
# _feishu_card_post <url> <template> <标题> <副标题> <正文markdown> <底部备注> [状态标签] [指标块JSON]
# template：blue 通知 / green 成功 / red 告警 / orange 待办 / purple 数据报告
# 结构：body 间距 16px + 内边距 16px 20px；正文 → 指标块 → hr → 小字灰色备注
# 注意：2.0 不支持 note 标签（会报 230099 拒收），底部备注用灰色 markdown 代替
_feishu_card_post() {
  local url="$1"; shift
  local template="$1" title="$2" subtitle="$3" body="$4" note="$5" tag="${6:-}" metric="${7:-}"
  local t s b n resp tag_json="" metric_json=""
  if [ -z "$url" ]; then
    echo "ERROR: feishu webhook not found" >&2
    return 1
  fi
  case "$template" in
    blue|green|red|orange|purple) ;;
    *) template="blue" ;;
  esac
  t="$(json_escape "$title")"
  s="$(json_escape "$subtitle")"
  b="$(json_escape "$body")"
  n="$(json_escape "$note")"
  if [ -n "$tag" ]; then
    tag_json=",\"text_tag_list\":[{\"tag\":\"text_tag\",\"text\":{\"tag\":\"plain_text\",\"content\":\"$(json_escape "$tag")\"},\"color\":\"$template\"}]"
  fi
  if [ -n "$metric" ]; then
    metric_json=",${metric}"
  fi
  resp="$(curl -s -m 30 --connect-timeout 10 -X POST "$url" \
    -H 'Content-Type: application/json' \
    -d "{\"msg_type\":\"interactive\",\"card\":{\"schema\":\"2.0\",\"header\":{\"template\":\"$template\",\"title\":{\"tag\":\"plain_text\",\"content\":\"$t\"},\"subtitle\":{\"tag\":\"plain_text\",\"content\":\"$s\"}$tag_json},\"body\":{\"vertical_spacing\":\"16px\",\"padding\":\"16px 20px\",\"elements\":[{\"tag\":\"markdown\",\"content\":\"$b\"}$metric_json,{\"tag\":\"hr\"},{\"tag\":\"markdown\",\"text_size\":\"notation\",\"content\":\"<font color='grey'>$n</font>\"}]}}}" 2>/dev/null)"
  # 卡片发送成功返回 code 0；失败则兜底极简卡（去掉指标块与容器间距）
  if printf '%s' "$resp" | grep -q '"code": *0'; then
    return 0
  fi
  resp="$(curl -s -m 30 --connect-timeout 10 -X POST "$url" \
    -H 'Content-Type: application/json' \
    -d "{\"msg_type\":\"interactive\",\"card\":{\"schema\":\"2.0\",\"header\":{\"template\":\"$template\",\"title\":{\"tag\":\"plain_text\",\"content\":\"$t\"},\"subtitle\":{\"tag\":\"plain_text\",\"content\":\"$s\"}$tag_json},\"body\":{\"elements\":[{\"tag\":\"markdown\",\"content\":\"$b\"},{\"tag\":\"hr\"},{\"tag\":\"markdown\",\"text_size\":\"notation\",\"content\":\"<font color='grey'>$n</font>\"}]}}}" 2>/dev/null)"
  if printf '%s' "$resp" | grep -q '"code": *0'; then
    return 0
  fi
  feishu_send_to "$url" "$title
$body
$note"
}

# 发卡片到告警机器人（炭火鸡）：feishu_card <template> <标题> <副标题> <正文> <备注> [标签] [指标块]
feishu_card() { _feishu_card_post "$FEISHU_URL" "$@"; }

# 发卡片到日报机器人（炭火鸽）：feishu_card_daily <同上>
# 注意：鸽的自定义关键词是“日报”，调用方须保证标题或正文里含“日报”二字
feishu_card_daily() { _feishu_card_post "$FEISHU_URL_DAILY" "$@"; }

# TCP 端口检测：check_tcp host port，通返回 0
check_tcp() {
  timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

# HTTP 检测：check_http url，拿到任何 HTTP 状态码返回 0
check_http() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 8 --max-time 15 "$1" 2>/dev/null)"
  [ -n "$code" ] && [ "$code" != "000" ]
}

# 北京时间（机器是 UTC，+8 小时；不用 tzdata）
now_cn() { date -u -d '+8 hours' '+%Y-%m-%d %H:%M'; }
today_cn() { date -u -d '+8 hours' '+%Y-%m-%d'; }
