#!/usr/bin/env bash
set -u

# =========================================================
# U_10 (상) 동일한 UID 금지 점검 | Ubuntu 24.04
# - 진단 기준: /etc/passwd 파일 내 동일한 UID를 사용하는 계정이 존재하면 취약
# - Rocky 논리 반영: cut -f3 -> sort -> uniq -d 로 중복 확인
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_10"
CATEGORY="account"
IS_AUTO=0  # UID 변경은 시스템 전반의 소유권 문제를 야기하므로 수동 조치(0)

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_10_1=0

# -------------------------
# 1) [U_10_1] 중복 UID 점검
# -------------------------
DUPLICATE_UIDS=""

if [ -f "/etc/passwd" ]; then
    # 3번째 필드(UID) 추출 -> 정렬 -> 중복된 값만 출력
    DUPLICATE_UIDS=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
fi

if [ -z "$DUPLICATE_UIDS" ]; then
    # 중복된 UID 없음 -> 양호
    FLAG_U_10_1=0
else
    # 중복된 UID 존재 -> 취약
    FLAG_U_10_1=1
fi

# -------------------------
# 2) VULN_STATUS
# -------------------------
IS_VUL=$FLAG_U_10_1

# -------------------------
# 3) Output (JSON)
# -------------------------
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
      "U_10_1": $FLAG_U_10_1
    },
    "timestamp": "$DATE"
  }
}
EOF