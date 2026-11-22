#!/usr/bin/env bash
# DataOnline 免费主机续费看门狗（每周日 08:30 北京时间跑一次）
# 平时静默；临近到期（到期前 60 天内）只发一张飞书提醒（炭火鸡），
# 之后不再重复打扰。过期不续会被自动锁定并删除。
#
# 续费规则（2026-11-22 官网条款核实）：
#   每 6 个月用续费码 FreeHostRE 免费续一次；续费按钮只在到期前 60 天内出现；
#   续费步骤：登录 my.dataonline.vn → 服务 → Free Hosting 1GB → 续费 →
#   输入续费码 FreeHostRE → 确认应付 0 VND → 提交。
#   注意：DataOnline 没有公开客户端 API，续费点击本身无法用脚本完成；
#   本脚本只负责临近时发一张提醒，续费操作由 Muse 经浏览器或用户手动完成。
#
# 提醒规则（用户 2026-11-23 定）：每个到期周期最多发一张卡。
#   到期前 60 天内第一次查到就发一张待续费卡（7 天内红色，其余橙色）；
#   如果部署得晚、第一次查到时已经过期，就发一张过期卡。发过就不再发。
#
# 续费后维护：把下面 EXPIRY 改成新的到期日，并清空状态目录
#   rm -rf /root/dataonline-renewal-state
# 下次运行会自动按新到期日重新开始计时（状态文件里记的旧到期日不一致时也会自动重置）。
#
# 测试：FAKE_TODAY=2027-03-23 ./dataonline-renewal-watch.sh --dry-run
#   （--dry-run 只打印将要发的内容，不发飞书；STATE_DIR 环境变量可指定测试用状态目录）
# 部署：小兔云 /root/dataonline-renewal-watch.sh + dataonline-renewal-watch.timer
#   （本地 workspace 这份只是编辑草稿，小兔云那份才是正式版）

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/monitor_common.sh"

EXPIRY="${EXPIRY:-2027-05-22}"
RENEW_CODE="FreeHostRE"
DOMAIN="host.hqyyk.loc.cc"
STATE_DIR="${STATE_DIR:-/root/dataonline-renewal-state}"
STATE_FILE="$STATE_DIR/notified"
STATUS_FILE="$STATE_DIR/status"

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
  feishu_card() { echo "DRY-RUN feishu_card template=$1 title=$2 subtitle=$3 body=$4 note=$5 tag=$6"; }
fi

TODAY="${FAKE_TODAY:-$(date +%F)}"
mkdir -p "$STATE_DIR"

expiry_s="$(date -d "$EXPIRY" +%s 2>/dev/null)"
today_s="$(date -d "$TODAY" +%s 2>/dev/null)"
if [ -z "$expiry_s" ] || [ -z "$today_s" ]; then
  echo "ERROR: bad date EXPIRY=$EXPIRY TODAY=$TODAY" >&2
  exit 1
fi
days_left=$(( (expiry_s - today_s) / 86400 ))

# 状态文件第一行记到期日；到期日变了（已续费并改了脚本）就重置提醒记录
if [ -f "$STATE_FILE" ]; then
  old_expiry="$(head -n1 "$STATE_FILE" | sed 's/^EXPIRY=//')"
  if [ "$old_expiry" != "$EXPIRY" ]; then
    printf 'EXPIRY=%s\n' "$EXPIRY" > "$STATE_FILE"
  fi
else
  printf 'EXPIRY=%s\n' "$EXPIRY" > "$STATE_FILE"
fi
printf 'days_left=%s\nexpiry=%s\nchecked=%s\n' "$days_left" "$EXPIRY" "$TODAY" > "$STATUS_FILE"

# 本周期已经发过那一张卡：不再打扰
if grep -qx "NOTIFIED" "$STATE_FILE" 2>/dev/null; then
  exit 0
fi

# 还没到续费窗口：静默
if [ "$days_left" -gt 60 ]; then
  exit 0
fi

send_card() {
  local template="$1" title="$2" body="$3" tag="$4"
  local metric note
  metric="$(metric_block "剩余天数" "${days_left} 天" "续费码" "$RENEW_CODE")"
  note="续费步骤：登录 my.dataonline.vn → 服务 → Free Hosting 1GB → 续费 → 输入续费码 FreeHostRE → 确认 0 VND 再提交。自动续费开着，提交前务必确认金额是 0。续费后把脚本里的到期日改成新的并清空状态目录。"
  feishu_card "$template" "$title" "$DOMAIN" "$body" "$note" "$tag" "$metric"
  printf 'NOTIFIED\n' >> "$STATE_FILE"
}

# 已过期（且本周期还没发过卡）：发一张过期卡
if [ "$days_left" -lt 0 ]; then
  send_card "red" "DataOnline 免费主机已过期" "主机 $DOMAIN 已过期 $(( -days_left )) 天（到期日 $EXPIRY），按条款会被自动锁定并删除。尽快登录客户区看还能不能续费，续不了就重新申请。" "已过期"
  exit 0
fi

# 在窗口内：发本周期唯一的一张待续费卡
if [ "$days_left" -le 7 ]; then
  template="red"
else
  template="orange"
fi
if [ "$days_left" -eq 0 ]; then
  when="今天到期"
else
  when="距到期还有 $days_left 天（到期日 $EXPIRY）"
fi
send_card "$template" "DataOnline 免费主机待续费" "主机 $DOMAIN $when，续费窗口已开。用续费码 $RENEW_CODE 可免费续 6 个月，过期不续会被自动锁定并删除。" "待续费"
exit 0
