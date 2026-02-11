#!/bin/bash

# [U-08] 관리자 그룹에 최소한의 계정 포함 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 관리자 그룹(root)에 불필요한 계정이 등록되어 있지 않은 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_08_1=0 
IS_VUL=0

# --- 점검 시작 ---

# /etc/group 파일에서 root 그룹 라인 추출
# 형식 -> root:x:0:user1,user2
ROOT_GROUP_LINE=$(grep "^root:" /etc/group)

# 4번째 필드(그룹원 목록) 추출
GROUP_MEMBERS=$(echo "$ROOT_GROUP_LINE" | cut -d: -f4)

# 공백 제거 (혹시 모를 공백 처리)
GROUP_MEMBERS=$(echo "$GROUP_MEMBERS" | tr -d ' ')

# 판단 로직
if [ -z "$GROUP_MEMBERS" ]; then
    # 1. 그룹원 목록이 비어있는 경우 -> 양호 (root의 Primary Group이므로 보통 비어있음)
    U_08_1=0
elif [ "$GROUP_MEMBERS" == "root" ]; then
    # 2. 그룹원에 'root'만 명시되어 있는 경우 -> 양호
    U_08_1=0
else
    # 3. 그 외 다른 계정이 포함된 경우 -> 취약
    # 예: "root,user1" 또는 "user1"
    U_08_1=1
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_08_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-08",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_08_1": $U_08_1
    },
    "timestamp": "$DATE"
  }
}
EOF