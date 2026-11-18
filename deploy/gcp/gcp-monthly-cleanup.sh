#!/bin/bash
# gcp-monthly-cleanup.sh — GCP 每月清理（2026-11-18 用户定：程序化，不再手动）
# 每月 15 号 04:00 北京时间跑一次（gcp-monthly-cleanup.timer）。
# 只清批准过的几类：apt 缓存/列表、ops-agent 大日志、journal、旧内核、/tmp 旧 m-ui 文件。
# 绝不碰：/opt/google-cloud-ops-agent、/root/.acme.sh、/etc/m-ui、当前内核；不做 blanket autoremove。
# 日志：/var/log/gcp-cleanup.log（每次运行前只保留最近 200 行）。
set -u

LOG=/var/log/gcp-cleanup.log
OPS_LOG=/var/log/google-cloud-ops-agent/subagents/logging-module.log

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

# 旧内核包列表：只选带版本号的 linux-image/linux-headers 包，且不含当前运行内核版本；
# 元包（linux-image-cloud-amd64 等，不带版本号）永远不选。输出每行一个包名。
old_kernel_pkgs() {
    local current
    current="$(uname -r)"
    dpkg -l 'linux-image-*' 'linux-headers-*' 2>/dev/null | awk '/^ii/{print $2}' | while read -r pkg; do
        case "$pkg" in
            linux-image-[0-9]*|linux-headers-[0-9]*)
                case "$pkg" in
                    *"$current"*) ;;  # 当前内核的包，跳过
                    *) echo "$pkg" ;;
                esac
                ;;
            *) ;;  # 元包或其他，跳过
        esac
    done
}

main() {
    # 日志封顶：只保留最近 200 行
    if [ -f "$LOG" ] && [ "$(wc -l < "$LOG")" -gt 200 ]; then
        tail -n 200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
    fi
    log "=== GCP monthly cleanup start ==="
    log "df before: $(df -h / | awk 'NR==2{print $2" total, "$3" used, "$4" avail, "$5}')"

    # 1. apt 缓存
    if apt-get clean >>"$LOG" 2>&1; then log "apt clean: ok"; else log "apt clean: FAILED"; fi

    # 2. 软件源列表 + 缓存索引，删完重建（apt update 失败重试一次）
    rm -rf /var/lib/apt/lists/* /var/cache/apt/pkgcache.bin /var/cache/apt/srcpkgcache.bin
    log "apt lists + pkgcache removed"
    apt_ok=0
    if apt-get update >>"$LOG" 2>&1; then
        apt_ok=1
    else
        log "apt update failed, retry in 60s"
        sleep 60
        if apt-get update >>"$LOG" 2>&1; then apt_ok=1; fi
    fi
    if [ "$apt_ok" = 1 ]; then log "apt update: ok (lists rebuilt)"; else log "apt update: FAILED twice, apt lists NOT rebuilt"; fi

    # 3. ops-agent 大日志（>50M 才处理）：被占用就截断，没占用就删除；无 fuser 时默认截断
    if [ -f "$OPS_LOG" ]; then
        size=$(stat -c%s "$OPS_LOG" 2>/dev/null || echo 0)
        if [ "$size" -gt 52428800 ]; then
            if command -v fuser >/dev/null 2>&1 && fuser -s "$OPS_LOG" 2>/dev/null; then
                truncate -s 0 "$OPS_LOG" && log "ops-agent log truncated (${size} bytes, was in use)"
            elif command -v fuser >/dev/null 2>&1; then
                rm -f "$OPS_LOG" && log "ops-agent log deleted (${size} bytes, not in use)"
            else
                truncate -s 0 "$OPS_LOG" && log "ops-agent log truncated (${size} bytes, no fuser)"
            fi
        else
            log "ops-agent log small (${size} bytes), skip"
        fi
    else
        log "ops-agent log absent, skip"
    fi

    # 4. journal：先 rotate（活动日志 vacuum 释放不了，2026-11-18 实测），再 vacuum 到 50M
    journalctl --rotate >>"$LOG" 2>&1
    if journalctl --vacuum-size=50M >>"$LOG" 2>&1; then
        log "journal vacuumed to 50M (now $(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMG]' | head -1))"
    else
        log "journal vacuum: FAILED"
    fi

    # 5. 旧内核：只 purge 非当前版本的版本化内核包；当前内核与元包不动
    old_pkgs=$(old_kernel_pkgs | tr '\n' ' ')
    if [ -n "$old_pkgs" ]; then
        log "purging old kernel packages: $old_pkgs"
        if apt-get purge -y $old_pkgs >>"$LOG" 2>&1; then
            log "old kernels purged"
        else
            log "old kernel purge: FAILED"
        fi
    else
        log "no old kernel packages, skip"
    fi

    # 6. /tmp 里 7 天以上的 m-ui .js 文件（只清顶层、只清 m-ui 开头）
    removed=$(find /tmp -maxdepth 1 -name 'm-ui*.js' -mtime +7 -print -delete 2>/dev/null | wc -l)
    log "/tmp old m-ui .js files removed: $removed"

    log "df after: $(df -h / | awk 'NR==2{print $2" total, "$3" used, "$4" avail, "$5}')"
    log "=== GCP monthly cleanup end ==="

    # 只有 apt update 两次都失败才返回非零（系统处于降级状态，需要人看）
    [ "$apt_ok" = 1 ]
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
