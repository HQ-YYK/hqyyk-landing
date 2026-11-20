#!/bin/bash
# 三机器人分流测试卡：炭火鸡（告警）+ 炭火鸽（日报）各发一张完整卡
# 炭火猿那张已由天翼 test-feishu.cmd 发出（code 0），这里只发鸡和鸽
# 一次性测试脚本，跑完即删，不进定时任务
source /root/monitor_common.sh
NOW="$(date '+%Y-%m-%d %H:%M')"

feishu_card green "炭火鸡测试卡" "三机器人分流测试 · $NOW" "告警通道测试：这张卡由炭火鸡（告警机器人）发出。服务器告警、预算提醒、清理失败、看守异常都会走这条通道。" "" "测试" "$(metric_block '机器人' '炭火鸡' '通道' '告警')"
echo "chicken rc=$?"

feishu_card_daily purple "日报测试卡 · 日报" "三机器人分流测试 · $NOW" "日报通道测试：这张卡由炭火鸽（日报机器人）发出。早间简报、学习消息、Feed 摘要都会走这条通道。" "" "测试" "$(metric_block '机器人' '炭火鸽' '通道' '日报')"
echo "dove rc=$?"
