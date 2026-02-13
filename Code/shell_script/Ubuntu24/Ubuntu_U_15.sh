#!/usr/bin/env bash
set -u

# =========================================================
# U_15 (상) 파일 및 디렉터리 소유자 설정 | Ubuntu 24.04
# - 진단 기준: 소유자(nouser) 또는 그룹(nogroup)이 없는 파일 존재 여부 점검
# - DB 정합성: IS_AUTO=0 (수동 조치 권장)
# - 최적화: -xdev(로컬 시스템만), -print -quit(발견 시 즉시 종료)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_15"
CATEGORY="file"
IS_AUTO=0

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_14_1=0

# -------------------------
# 1) 소유자/그룹 없는 파일 탐색
# -------------------------
# 하나라도 발견되면 즉시 경로 반환 후 종료
FOUND_ORPHAN=$(find / -xdev \( -nouser -o -nogroup \) -print -quit 2>/dev/null)

if [ -n "$FOUND_ORPHAN" ]; then
    FLAG_U_15_1=1
else
    FLAG_U_15_1=0
fi

# -------------------------
# 2) Output (JSON)
# -------------------------
IS_VUL=$FLAG_U_15_1

cat <<EOF
{
  "meta": {
    "hostname": "$HOST",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": {
      "U_15_1": $FLAG_U_15_1
    },
    "timestamp": "$DATE"
  }
}
EOF