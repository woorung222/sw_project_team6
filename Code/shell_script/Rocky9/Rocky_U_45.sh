#!/bin/bash

# [U-45] 메일 서비스 버전 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 메일 서비스(Sendmail, Postfix, Exim) 버전의 최신성 점검
# DB 정합성 : IS_AUTO=0 (서비스 업데이트 위험으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_45_1=0; U_45_2=0; U_45_3=0; U_45_4=0; U_45_5=0; U_45_6=0
IS_VUL=0
IS_AUTO=0 

# --- 함수 정의: 서비스 존재 및 버전 점검 ---
check_mail_version() {
    local PKG_NAME=$1
    local FLAG_EXIST=$2
    local FLAG_VER=$3
    
    # 1. 패키지 설치 또는 프로세스 실행 여부 확인
    if rpm -q "$PKG_NAME" >/dev/null 2>&1 || ps -e -o comm | grep -v "grep" | grep -xw "$PKG_NAME" >/dev/null 2>&1; then
        eval "$FLAG_EXIST=1"
        # 2. 업데이트 필요 여부 확인 (취약 버전 판단)
        if dnf check-update "$PKG_NAME" -q | grep -w "$PKG_NAME" >/dev/null 2>&1; then
            eval "$FLAG_VER=1"
        fi
    fi
}

check_mail_version "sendmail" "U_45_1" "U_45_2"
check_mail_version "postfix"  "U_45_3" "U_45_4"
check_mail_version "exim"     "U_45_5" "U_45_6"

# 최종 결과: 하나라도 버전 미흡(2, 4, 6)이 있으면 취약
[ "$U_45_2" -eq 1 ] || [ "$U_45_4" -eq 1 ] || [ "$U_45_6" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-45",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { 
        "U_45_1": $U_45_1, "U_45_2": $U_45_2, 
        "U_45_3": $U_45_3, "U_45_4": $U_45_4, 
        "U_45_5": $U_45_5, "U_45_6": $U_45_6 
    },
    "timestamp": "$DATE"
  }
}
EOF