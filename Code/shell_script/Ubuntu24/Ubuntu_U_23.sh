#!/usr/bin/env bash
set -u

# =========================================================
# U_23 (상) SUID, SGID, Sticky bit 설정 파일 점검 | Ubuntu 24.04
# - 진단 기준: 불필요한 주요 파일에 SUID/SGID 설정 여부 점검
# - DB 정합성: IS_AUTO=0 (애플리케이션 오동작 위험으로 수동 조치)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_23"
CATEGORY="file"
IS_AUTO=0

U_23_1=0

# Ubuntu 환경에 맞춘 점검 대상 파일 리스트
CHECK_LIST=(
    "/sbin/dump" "/sbin/restore"
    "/usr/bin/at"
    "/usr/bin/lpq" "/usr/bin/lpr" "/usr/bin/lprm"
    "/usr/sbin/lpc" "/usr/bin/newgrp"
    "/usr/bin/traceroute"
)

for target in "${CHECK_LIST[@]}"; do
    if [ -f "$target" ]; then
        # stat으로 특수 권한(4000, 2000) 존재 여부 확인
        # %a의 4번째 자리(있을 경우) 또는 8진수 계산
        PERM=$(stat -c "%a" "$target")
        # 4자리 권한 중 첫 자리가 2(SGID), 4(SUID), 6(둘다) 인지 확인
        if [ ${#PERM} -eq 4 ]; then
            FIRST_DIGIT=${PERM:0:1}
            if [[ "$FIRST_DIGIT" =~ [246] ]]; then
                U_23_1=1
                break
            fi
        fi
    fi
done

IS_VUL=$U_23_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_23_1": $U_23_1 },
    "timestamp": "$DATE"
  }
}
EOF