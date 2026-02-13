#!/usr/bin/env bash
set -u

# =========================================================
# U_08 (상) 관리자 그룹에 최소한의 계정 포함 점검 | Ubuntu 24.04
# - 진단 기준: 관리자 그룹(root)에 불필요한 계정이 등록되어 있지 않은 경우 양호
# - Rocky 논리 반영: /etc/group 내 root 그룹원 확인
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_08"
CATEGORY="account"
IS_AUTO=0  # 계정/그룹 설정 변경은 위험하므로 수동 조치(0)

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_08_1=0

# -------------------------
# 1) [U_08_1] root 그룹 멤버 점검
# -------------------------
GROUP_MEMBERS=""

if [ -f "/etc/group" ]; then
    # root 그룹 라인 추출 (예: root:x:0:user1)
    # 4번째 필드가 그룹원 목록
    GROUP_MEMBERS=$(grep "^root:" /etc/group | cut -d: -f4 | tr -d ' ')
fi

# 판단 로직
if [ -z "$GROUP_MEMBERS" ]; then
    # 1. 그룹원 목록이 비어있는 경우 -> 양호 (root가 Primary Group인 경우 보통 비어있음)
    FLAG_U_08_1=0
elif [ "$GROUP_MEMBERS" = "root" ]; then
    # 2. 그룹원에 'root'만 명시되어 있는 경우 -> 양호
    FLAG_U_08_1=0
else
    # 3. 그 외 다른 계정이 포함된 경우 -> 취약
    FLAG_U_08_1=1
fi

# -------------------------
# 2) VULN_STATUS
# -------------------------
IS_VUL=$FLAG_U_08_1

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
      "U_08_1": $FLAG_U_08_1
    },
    "timestamp": "$DATE"
  }
}
EOF