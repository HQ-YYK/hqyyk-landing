#!/bin/bash
# 中转站每日自动签到：每天 08:10（北京时间）跑一次
# 成功/已签到只记日志；失败（网络、鉴权过期、意外返回）才发飞书告警
# 凭证只存在小兔云 /root/relay-checkin/credentials（600 权限），绝不进聊天与汇报
# v3 接 5 站：烁、Orbitix、hkai（New API，PAT）+ Sidrune（Sub2API，refresh_token 轮换）+ 蹬蹬堂（自研站，会话 Cookie）
# v3.1（2026-11-18）：蹬蹬堂重复签到 409 按已签到处理（实测 error 文案“今天已经签到过了”）
# 深空（标准签到已关闭 + Turnstile 开着，定制接口未确认）暂不接
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/monitor_common.sh"

CRED_FILE="/root/relay-checkin/credentials"
STATUS_DIR="/root/relay-checkin"
LOG_FILE="/root/relay-checkin.log"
mkdir -p "$STATUS_DIR"

log() { echo "[$(now_cn)] $*" >> "$LOG_FILE"; }

# 凭证缺失直接告警（部署问题，需处理）
if [ ! -f "$CRED_FILE" ]; then
  feishu_card red "签到失败" "凭证文件缺失" "中转站自动签到凭证文件不存在，请检查部署。" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "签到" "凭证" "状态" "缺失")"
  log "FATAL: credentials file missing"
  exit 1
fi
# shellcheck disable=SC1091
. "$CRED_FILE"

TODAY="$(date -u -d '+8 hours' +%F)"

# do_checkin <名字> <基础地址> <PAT> <用户ID> [是否试旧路由 1/0]
# 返回 0=成功或已签到，1=失败（已发告警）
do_checkin() {
  local name="$1" base="$2" pat="$3" uid="$4" try_legacy="${5:-0}"
  local url body http tmp quota msg
  if [ -z "$pat" ]; then
    feishu_card red "签到失败" "$name 凭证缺失" "**$name** 的访问令牌未配置，请重新生成并写入凭证文件。" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "$name" "状态" "凭证缺失")"
    log "$name: SKIP no credential"
    return 1
  fi
  url="$base/api/user/checkin"
  tmp="$(mktemp)"
  http="$(curl -s -m 30 -o "$tmp" -w '%{http_code}' -X POST "$url" -H "Authorization: Bearer $pat" -H "New-Api-User: $uid" 2>/dev/null)"
  body="$(cat "$tmp" 2>/dev/null)"; rm -f "$tmp"
  # 404 且允许试旧路由时，改试 /api/user/signin（旧版路由名）
  if [ "$http" = "404" ] && [ "$try_legacy" = "1" ]; then
    log "$name: /api/user/checkin 404，改试旧路由 /api/user/signin"
    url="$base/api/user/signin"
    tmp="$(mktemp)"
    http="$(curl -s -m 30 -o "$tmp" -w '%{http_code}' -X POST "$url" -H "Authorization: Bearer $pat" -H "New-Api-User: $uid" 2>/dev/null)"
    body="$(cat "$tmp" 2>/dev/null)"; rm -f "$tmp"
  fi
  if printf '%s' "$body" | grep -q '"success": *true'; then
    quota="$(printf '%s' "$body" | grep -o '"quota_awarded": *[0-9]*' | grep -o '[0-9]*$')"
    log "$name: OK signed, quota_awarded=${quota:-?}"
    echo "$TODAY|OK|signed|${quota:-}" > "$STATUS_DIR/$name"
    return 0
  fi
  if printf '%s' "$body" | grep -qi 'already checked in today\|已签到'; then
    log "$name: OK already signed today"
    echo "$TODAY|OK|already" > "$STATUS_DIR/$name"
    return 0
  fi
  # 失败：区分鉴权过期与其他
  msg="$(printf '%s' "$body" | grep -o '"message": *"[^"]*"' | head -n 1 | sed -e 's/^"message": *"//' -e 's/"$//')"
  [ -z "$msg" ] && msg="HTTP $http，无返回内容"
  if printf '%s' "$body" | grep -qi 'AUTH_UNAUTHORIZED\|invalid access token\|无权进行此操作'; then
    feishu_card red "签到失败" "$name 鉴权过期" "**$name** 签到鉴权失败（$msg），访问令牌可能已过期或被覆盖，请重新生成。" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "$name" "状态" "鉴权过期")"
  else
    feishu_card red "签到失败" "$name 签到失败" "**$name** 签到失败（HTTP $http）：$msg" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "$name" "状态" "失败")"
  fi
  log "$name: FAIL http=$http msg=$msg"
  echo "$TODAY|FAIL|$http|$msg" > "$STATUS_DIR/$name"
  return 1
}

# do_sidrune：Sidrune（Sub2API）福利签到
# 流程：refresh_token 换新 auth_token（refresh_token 会轮换，成功后立即写回凭证文件）
#       → GET /welfare/profile 看今日是否已签 → 未签则 POST /welfare/checkin
# 返回 0=成功或已签到，1=失败（已发告警）
do_sidrune() {
  local base="https://cn.sidrune.ai"
  local rt="$SIDRUNE_REFRESH"
  local tmp http body new_rt access_token checked streak reward msg title
  if [ -z "$rt" ]; then
    feishu_card red "签到失败" "Sidrune 凭证缺失" "**Sidrune** 的 refresh_token 未配置，请从浏览器 localStorage 重新取回并写入凭证文件。" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "Sidrune" "状态" "凭证缺失")"
    log "sidrune: SKIP no credential"
    return 1
  fi
  # 1. 刷新 token
  tmp="$(mktemp)"
  http="$(curl -s -m 30 -o "$tmp" -w '%{http_code}' -X POST "$base/api/v1/auth/refresh" -H "Content-Type: application/json" -d "{\"refresh_token\":\"$rt\"}" 2>/dev/null)"
  body="$(cat "$tmp" 2>/dev/null)"; rm -f "$tmp"
  access_token="$(printf '%s' "$body" | grep -o '"access_token":"[^"]*"' | head -n 1 | sed -e 's/^"access_token":"//' -e 's/"$//')"
  new_rt="$(printf '%s' "$body" | grep -o '"refresh_token":"[^"]*"' | head -n 1 | sed -e 's/^"refresh_token":"//' -e 's/"$//')"
  if [ "$http" != "200" ] || [ -z "$access_token" ] || [ -z "$new_rt" ]; then
    msg="$(printf '%s' "$body" | grep -o '"message":"[^"]*"' | head -n 1 | sed -e 's/^"message":"//' -e 's/"$//')"
    [ -z "$msg" ] && msg="HTTP $http，无返回内容"
    if [ "$http" = "000" ]; then
      title="Sidrune 网络异常"
    elif printf '%s' "$body" | grep -qi '401\|expired\|invalid\|unauthorized\|过期'; then
      title="Sidrune 鉴权过期"
    else
      title="Sidrune 刷新失败"
    fi
    feishu_card red "签到失败" "$title" "**Sidrune** 刷新 token 失败（$msg）。鉴权过期时请重新登录面板后更新 refresh_token。" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "Sidrune" "状态" "刷新失败")"
    log "sidrune: FAIL refresh http=$http msg=$msg"
    echo "$TODAY|FAIL|refresh|$msg" > "$STATUS_DIR/sidrune"
    return 1
  fi
  # 2. 立即写回轮换后的 refresh_token（旧 token 已失效，丢了就得手动重取）
  tmp="$(mktemp)"
  grep -v '^SIDRUNE_REFRESH=' "$CRED_FILE" > "$tmp"
  printf "SIDRUNE_REFRESH='%s'\n" "$new_rt" >> "$tmp"
  chmod 600 "$tmp"
  if ! mv "$tmp" "$CRED_FILE"; then
    rm -f "$tmp"
    feishu_card red "签到失败" "Sidrune 凭证写回失败" "**Sidrune** 刷新成功但新 refresh_token 写回凭证文件失败，旧 token 已失效，请手动重新取回。" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "Sidrune" "状态" "写回失败")"
    log "sidrune: FAIL credential rewrite failed"
    echo "$TODAY|FAIL|credwrite|" > "$STATUS_DIR/sidrune"
    return 1
  fi
  # 3. 查今日是否已签
  tmp="$(mktemp)"
  http="$(curl -s -m 30 -o "$tmp" -w '%{http_code}' "$base/api/v1/welfare/profile" -H "Authorization: Bearer $access_token" 2>/dev/null)"
  body="$(cat "$tmp" 2>/dev/null)"; rm -f "$tmp"
  checked="$(printf '%s' "$body" | grep -o '"checked_in_today":\(true\|false\)' | sed 's/.*://')"
  streak="$(printf '%s' "$body" | grep -o '"current_streak":[0-9]*' | grep -o '[0-9]*$')"
  if [ "$checked" = "true" ]; then
    log "sidrune: OK already signed today (streak ${streak:-?})"
    echo "$TODAY|OK|already|streak=${streak:-}" > "$STATUS_DIR/sidrune"
    return 0
  fi
  # 4. 签到
  tmp="$(mktemp)"
  http="$(curl -s -m 30 -o "$tmp" -w '%{http_code}' -X POST "$base/api/v1/welfare/checkin" -H "Authorization: Bearer $access_token" 2>/dev/null)"
  body="$(cat "$tmp" 2>/dev/null)"; rm -f "$tmp"
  if printf '%s' "$body" | grep -q '"code":0'; then
    streak="$(printf '%s' "$body" | grep -o '"streak_day":[0-9]*' | grep -o '[0-9]*$')"
    reward="$(printf '%s' "$body" | grep -o '"reward_amount":[0-9.]*' | grep -o '[0-9.]*$')"
    log "sidrune: OK signed, streak_day=${streak:-?}, reward=${reward:-?}"
    echo "$TODAY|OK|signed|streak=${streak:-}|reward=${reward:-}" > "$STATUS_DIR/sidrune"
    return 0
  fi
  msg="$(printf '%s' "$body" | grep -o '"message":"[^"]*"' | head -n 1 | sed -e 's/^"message":"//' -e 's/"$//')"
  [ -z "$msg" ] && msg="HTTP $http，无返回内容"
  feishu_card red "签到失败" "Sidrune 签到失败" "**Sidrune** 签到失败（HTTP $http）：$msg" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "Sidrune" "状态" "失败")"
  log "sidrune: FAIL checkin http=$http msg=$msg"
  echo "$TODAY|FAIL|checkin|$msg" > "$STATUS_DIR/sidrune"
  return 1
}

# do_dengdengtang：蹬蹬堂订阅共享池签到（自研站，非 New API）
# 接口（2026-11-18 从池子页内联 JS 确认）：POST /ipcheck/api/pool/checkin，
#   Content-Type: application/json，空 JSON 体 {}，Cookie 会话鉴权，无 CSRF、无验证码。
#   成功返回 {"points":N,"balance":N,"streak":N}；重复签到返回 HTTP 409 + error“今天已经签到过了”
#   （2026-11-18 实测；注意“已经签到”不含“已签到”子串，匹配须用“已经签到/签到过”）。
# 凭证：DENGDENGTANG_COOKIE（本站会话 Cookie 的 name=value，由用户从自己 Chrome 里复制，
#   直接写进小兔云凭证文件，Muse 不经手）。Cookie 过期时发鉴权过期卡，重新复制即可。
# 返回 0=成功或已签到，1=失败（已发告警）
do_dengdengtang() {
  local base="https://ai01.teleapi.top"
  local cookie="$DENGDENGTANG_COOKIE"
  local tmp http body points balance streak msg
  if [ -z "$cookie" ]; then
    feishu_card red "签到失败" "蹬蹬堂凭证缺失" "**蹬蹬堂**的会话 Cookie 未配置，请从浏览器复制后写入凭证文件。" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "蹬蹬堂" "状态" "凭证缺失")"
    log "dengdengtang: SKIP no credential"
    return 1
  fi
  tmp="$(mktemp)"
  http="$(curl -s -m 30 -o "$tmp" -w '%{http_code}' -X POST "$base/ipcheck/api/pool/checkin" -H "Content-Type: application/json" -H "Cookie: $cookie" -d '{}' 2>/dev/null)"
  body="$(cat "$tmp" 2>/dev/null)"; rm -f "$tmp"
  if printf '%s' "$body" | grep -q '"points": *[0-9]'; then
    points="$(printf '%s' "$body" | grep -o '"points": *[0-9]*' | grep -o '[0-9]*$')"
    balance="$(printf '%s' "$body" | grep -o '"balance": *[0-9]*' | grep -o '[0-9]*$')"
    streak="$(printf '%s' "$body" | grep -o '"streak": *[0-9]*' | grep -o '[0-9]*$')"
    log "dengdengtang: OK signed, points=${points:-?}, balance=${balance:-?}, streak=${streak:-?}"
    echo "$TODAY|OK|signed|points=${points:-}|balance=${balance:-}|streak=${streak:-}" > "$STATUS_DIR/dengdengtang"
    return 0
  fi
  if printf '%s' "$body" | grep -qi '已经签到\|已签到\|签到过\|already'; then
    log "dengdengtang: OK already signed today"
    echo "$TODAY|OK|already" > "$STATUS_DIR/dengdengtang"
    return 0
  fi
  msg="$(printf '%s' "$body" | grep -o '"error": *"[^"]*"' | head -n 1 | sed -e 's/^"error": *"//' -e 's/"$//')"
  [ -z "$msg" ] && msg="HTTP $http，无返回内容"
  if [ "$http" = "401" ] || [ "$http" = "302" ] || printf '%s' "$body" | grep -qi '未登录\|not logged in\|unauthorized\|登录过期\|login'; then
    feishu_card red "签到失败" "蹬蹬堂鉴权过期" "**蹬蹬堂**签到鉴权失败（$msg），会话 Cookie 可能已过期，请从浏览器重新复制后更新凭证文件。" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "蹬蹬堂" "状态" "鉴权过期")"
  else
    feishu_card red "签到失败" "蹬蹬堂签到失败" "**蹬蹬堂**签到失败（HTTP $http）：$msg" "时间：$(now_cn) · 小兔云签到" "签到" "$(metric_block "站点" "蹬蹬堂" "状态" "失败")"
  fi
  log "dengdengtang: FAIL http=$http msg=$msg"
  echo "$TODAY|FAIL|$http|$msg" > "$STATUS_DIR/dengdengtang"
  return 1
}

do_checkin "shuo" "https://elysia.h-e.top" "$SHUO_PAT" "40529" "1"
do_checkin "orbitix" "https://new.orbitix.site" "$ORBITIX_PAT" "2705" "0"
do_checkin "hkai" "https://share.hkai25.top" "$HKAI_PAT" "3437" "0"
do_sidrune
do_dengdengtang

# 日志轮转：只留最后 300 行
if [ -f "$LOG_FILE" ]; then
  tail -n 300 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
fi
