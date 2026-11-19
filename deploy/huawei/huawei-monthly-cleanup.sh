#!/bin/bash
# huawei-monthly-cleanup.sh — 华为云 Flexus L 新加坡每月清理（2026-11-18 用户定：程序化，不再手动）
# 每月 15 号 04:30 北京时间跑一次（huawei-monthly-cleanup.timer）。
# 只清批准过的几类：apt 缓存/列表、journal（只留 7 天）、btmp、7 天以上的 cert-retry.log、旧内核。
# 绝不碰：/root/huawei-sg-key.pem、/root/hqyyk-443.conf、/var/log/hostguard、当前内核；不做 blanket autoremove。
# 日志：/var/log/huawei-cleanup.log（每次运行前只保留最近 200 行）。
set -u

LOG=/var/log/huawei-cleanup.log
BTMP=/var/log/btmp
CERT_DIR=/root

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

# 旧内核包列表：只选带版本号的 linux-image/linux-headers 包，且不含当前运行内核版本；
# 元包（linux-image-amd64 等，不带版本号）永远不选。输出每行一个包名。
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
    log "=== Huawei monthly cleanup start ==="
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

    # 3. journal：先 rotate（活动日志 vacuum 释放不了，2026-11-18 实测），再只留 7 天
    #    （journal 仅 37M，vacuum-size=50M 清不出东西，用 vacuum-time=7d）
    journalctl --rotate >>"$LOG" 2>&1
    if journalctl --vacuum-time=7d >>"$LOG" 2>&1; then
        log "journal vacuumed to 7d (now $(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMG]' | head -1))"
    else
        log "journal vacuum: FAILED"
    fi

    # 4. btmp（登录失败记录）：截断即可
    if [ -f "$BTMP" ]; then
        if truncate -s 0 "$BTMP" 2>>"$LOG"; then log "btmp truncated"; else log "btmp truncate: FAILED"; fi
    else
        log "btmp absent, skip"
    fi

    # 5. cert-retry.log：7 天以上才删（2026-11-17 审计定的保留期）
    removed=$(find "$CERT_DIR" -maxdepth 1 -name 'cert-retry.log' -mtime +7 -print -delete 2>/dev/null | wc -l)
    log "old cert-retry.log removed: $removed"

    # 6. 旧内核：只 purge 非当前版本的版本化内核包；当前内核与元包不动
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

    log "df after: $(df -h / | awk 'NR==2{print $2" total, "$3" used, "$4" avail, "$5}')"
    log "=== Huawei monthly cleanup end ==="

    # 只有 apt update 两次都失败才返回非零（系统处于降级状态，需要人看）
    [ "$apt_ok" = 1 ]
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
