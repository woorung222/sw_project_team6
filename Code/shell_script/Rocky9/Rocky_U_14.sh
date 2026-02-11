#!/bin/bash

# [U-14] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 (실제 가이드명: root 홈, 패스 디렉터리 권한 및 패스 설정)
# 점검 내용: root 계정의 PATH 환경변수에 “.”(마침표)이 포함 여부 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우 양호
#            (맨 마지막에 있는 경우는 양호로 간주, 단 보안상 없는 것이 권장됨)

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_14_1=0 # 0: 양호, 1: 취약
IS_VUL=0

# --- 점검 시작 ---
# root 계정의 PATH 환경변수 확인
# 스크립트가 root 권한으로 실행되므로 현재 환경변수 $PATH를 점검하면 됨.

CURRENT_PATH=$PATH

# 점검 로직:
# 1. 맨 앞에 .이 있는지 확인 (예: .:...)
# 2. 중간에 .이 있는지 확인 (예: ...:.:...)
# 3. 참고: 빈 문자열(::)도 .으로 취급되나, 가이드 명시 기준인 "." 문자 위주로 점검

# grep 정규식 설명:
# ^\.   : 문자열 시작이 . 인 경우 (맨 앞)
# ^\.:  : 문자열 시작이 .: 인 경우 (맨 앞이고 뒤에 경로가 이어짐)
# :\.:  : 중간에 :.: 이 포함된 경우 (중간)
#
# 주의: 맨 뒤에 있는 경우(:.$)는 가이드상 '조치 방법'에 "마지막으로 이동하도록 설정"이라고 되어 있으므로 양호로 판단.

if echo "$CURRENT_PATH" | grep -E '^\.|:\.:' > /dev/null; then
    # 취약 패턴 발견
    U_14_1=1
    IS_VUL=1
else
    # 패턴 미발견 (양호)
    U_14_1=0
    IS_VUL=0
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-14",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_14_1": $U_14_1
    },
    "timestamp": "$DATE"
  }
}
EOF