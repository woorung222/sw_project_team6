#!/bin/bash

# [U-31] 홈디렉토리 소유자 및 권한 설정
set -u

FLAG_ID="U-31"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")
U_31_1=0; IS_VUL=0

# UID 1000 이상인 일반 사용자 홈디렉터리만 추출 (시스템 계정 제외하여 오진 방지)
USERS=$(awk -F: '$3>=1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false" {print $1":"$6}' /etc/passwd)

for u in $USERS; do
    uname=${u%%:*}
    uhome=${u#*:}
    
    # 디렉터리이며, 심볼릭 링크가 아닌 경우만 점검
    if [[ -d "$uhome" && ! -L "$uhome" ]]; then
        OWNER=$(run_cmd "[U_31_1] $uhome 소유자 확인" "stat -c '%U' '$uhome'")
        PERM=$(run_cmd "[U_31_1] $uhome 권한 확인" "stat -c '%a' '$uhome'")
        OTHER_P=${PERM: -1}
        
        if [[ "$OWNER" != "$uname" ]]; then
            U_31_1=1
            log_basis "[U_31_1] $uname 의 홈($uhome) 소유자가 본인이 아님 ($OWNER)" "취약"
        fi
        
        if [[ "$OTHER_P" =~ [2367] ]]; then
            U_31_1=1
            log_basis "[U_31_1] $uhome 권한($PERM)에 타인 쓰기 권한 있음" "취약"
        fi
    fi
done

if [[ $U_31_1 -eq 0 ]]; then
    log_basis "[U_31_1] 모든 일반 사용자 홈 디렉터리 설정 양호" "양호"
fi

IS_VUL=$U_31_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_31_1": $U_31_1
    },
    "timestamp": "$DATE"
  }
}
EOF