#!/bin/bash
# m-ui 自动升级检查（GCP 主机，/root/mui-update-check.sh）
# 定时：systemd timer，每两月 1 号 03:00（北京时间），见 mui-update-check.timer
# 流程：查已装版本 vs GitHub 最新稳定版 → 有新版写 pending 状态 → 睡 15 分钟 → 升级 → 写 done/failed 状态
# 状态文件 /var/www/html/mui-update.json 由 nginx 对外提供（location = /mui-update.json），小兔云轮询后推飞书。
# TODO（部署时在机上验证）：① 版本检测命令（m-ui version / --version 是否可用，不行改面板 API 或版本文件）；
# ② 安装脚本是否完全非交互（若有提示需加应答）；③ nginx 配置文件路径；④ timer 的 Timezone 是否生效（systemctl list-timers 核对下次触发）。
set -u
STATUS_FILE=/var/www/html/mui-update.json
LOG=/root/mui-update.log
SKIP_VERSIONS=""   # 空格分隔，如 "0.7.17"（默认不跳过任何版本）
REPO="Maoyangui/m-ui"

log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; tail -n 500 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; }
write_status() { printf '%s\n' "$1" > "$STATUS_FILE.tmp" && mv "$STATUS_FILE.tmp" "$STATUS_FILE"; }

# 1. 已装版本（多方法依次尝试）
installed=""
if command -v m-ui >/dev/null 2>&1; then
  installed=$(m-ui version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
if [ -z "$installed" ] && [ -x /usr/local/bin/m-ui ]; then
  installed=$(/usr/local/bin/m-ui --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
if [ -z "$installed" ]; then
  log "ERROR: 无法确定已装 m-ui 版本，退出"
  write_status "{\"status\":\"failed\",\"reason\":\"cannot detect installed version\",\"at\":\"$(date -Iseconds)\"}"
  exit 1
fi

# 2. GitHub 最新稳定版（releases/latest 只返回非预发布版）
latest=$(curl -fsSL --max-time 30 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep -m1 '"tag_name"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
if [ -z "$latest" ]; then
  log "ERROR: 无法获取 GitHub 最新版本，退出"
  exit 1
fi

now=$(date -Iseconds)
if [ "$installed" = "$latest" ]; then
  log "已是最新版 $installed，无需升级"
  write_status "{\"status\":\"up-to-date\",\"version\":\"$installed\",\"at\":\"$now\"}"
  exit 0
fi
for s in $SKIP_VERSIONS; do
  if [ "$latest" = "$s" ]; then
    log "最新版 $latest 在跳过列表里，不升级"
    write_status "{\"status\":\"skipped\",\"current\":\"$installed\",\"latest\":\"$latest\",\"at\":\"$now\"}"
    exit 0
  fi
done

# 3. 有新版：写 pending，等 15 分钟（让小兔云先把通知推出去）
log "发现新版：$installed -> $latest，15 分钟后升级"
write_status "{\"status\":\"pending\",\"current\":\"$installed\",\"latest\":\"$latest\",\"at\":\"$now\"}"
sleep 900

# 4. 升级（重跑官方安装脚本；先下载到本地验非空，再非交互运行，超时 10 分钟）
log "开始升级到 $latest"
tmp=/root/.mui-install.sh
up_ok=0
if curl -fsSL --max-time 60 "https://raw.githubusercontent.com/Maoyangui/m-ui/main/deploy/install.sh" -o "$tmp" && [ -s "$tmp" ]; then
  if timeout 600 bash "$tmp" </dev/null >> "$LOG" 2>&1; then up_ok=1; fi
else
  log "ERROR: 下载安装脚本失败"
fi
rm -f "$tmp"

# 5. 验证：版本号 + 面板可达
sleep 5
new_ver=""
if command -v m-ui >/dev/null 2>&1; then
  new_ver=$(m-ui version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
if [ -z "$new_ver" ] && [ -x /usr/local/bin/m-ui ]; then
  new_ver=$(/usr/local/bin/m-ui --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
panel_ok=0
if curl -fsSkL --max-time 15 "https://127.0.0.1:2053/" >/dev/null 2>&1; then panel_ok=1; fi
now=$(date -Iseconds)
if [ "$up_ok" = "1" ] && [ "$new_ver" = "$latest" ] && [ "$panel_ok" = "1" ]; then
  log "升级成功：$installed -> $latest，面板正常"
  write_status "{\"status\":\"done\",\"current\":\"$installed\",\"latest\":\"$latest\",\"at\":\"$now\"}"
else
  log "ERROR: 升级验证失败（up_ok=$up_ok new_ver=$new_ver panel_ok=$panel_ok）"
  write_status "{\"status\":\"failed\",\"current\":\"$installed\",\"latest\":\"$latest\",\"reason\":\"verify failed up_ok=$up_ok new_ver=$new_ver panel_ok=$panel_ok\",\"at\":\"$now\"}"
fi
