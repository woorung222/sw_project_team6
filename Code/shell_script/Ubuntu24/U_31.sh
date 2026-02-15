#!/usr/bin/env bash
set -u

# =========================================================
# U_31 (중) 홈 디렉터리 소유자 및 권한 설정 | Ubuntu 24.04
# - 진단 기준: 홈 디렉터리 소유자 본인 여부 및 타인 쓰기 금지
# - DB 정합성: IS_AUTO=1
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_31"
CATEGORY="file"
IS_AUTO=1

U_31_1=0

# 시스템 모든 사용자의 홈 디렉터리 점검
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    # /home 아래에 있거나 /root인 경우만 정밀 점검 (시스템 계정 오탐 방지)
    if [[ "$HOMEDIR" == /home/* || "$HOMEDIR" == "/root" ]]; then
        if [ -d "$HOMEDIR" ]; then
            OWNER=$(stat -c "%U" "$HOMEDIR")
            PERM_STR=$(stat -c "%A" "$HOMEDIR")
            
            # 소유자 불일치 또는 Other Write 권한(8번째 자리 w) 발견 시 취약
            if [ "$OWNER" != "$USERNAME" ] || [ "${PERM_STR:8:1}" == "w" ]; then
                U_31_1=1
                break
            fi
        fi
    fi
done < /etc/passwd

IS_VUL=$U_31_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_31_1": $U_31_1 },
    "timestamp": "$DATE"
  }
}
EOF