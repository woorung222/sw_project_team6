#!/bin/bash

# [U-10] 동일한 UID 금지 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /etc/passwd 파일 내 동일한 UID를 사용하는 계정이 존재하면 취약

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_10_1=0 
IS_VUL=0
VULN_DETAILS=""

# --- 점검 시작 ---

# 1. /etc/passwd에서 UID(3번째 필드) 추출 -> 정렬 -> 중복된 값만 출력(uniq -d)
DUPLICATE_UIDS=$(cut -d: -f3 /etc/passwd | sort | uniq -d)

if [ -z "$DUPLICATE_UIDS" ]; then
    # 중복된 UID가 없음 (양호)
    U_10_1=0
else
    # 중복된 UID가 존재함 (취약)
    U_10_1=1
    
    # (선택 사항) 어떤 계정들이 중복인지 확인하여 변수에 담음 (디버깅용)
    # for uid in $DUPLICATE_UIDS; do
    #     ACCOUNTS=$(awk -F: -v uid="$uid" '$3 == uid {print $1}' /etc/passwd)
    #     VULN_DETAILS+="UID($uid):$ACCOUNTS "
    # done
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_10_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-10",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "account",
    "flag": {
      "U_10_1": $U_10_1
    },
    "timestamp": "$DATE"
  }
}
EOF