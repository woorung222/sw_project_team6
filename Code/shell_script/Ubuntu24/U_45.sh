#!/usr/bin/env bash
set -u

# =========================================================
# U_45 (상) 메일 서비스 버전 점검 | Ubuntu 24.04
# - 진단 기준: 메일 서비스 존재 여부(1/3/5) 및 버전 최신성(2/4/6) 점검
# - DB 정합성: IS_AUTO=0 (수동 조치 권장)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_45"
CATEGORY="service"
IS_AUTO=0

U_45_1=0; U_45_2=0; U_45_3=0; U_45_4=0; U_45_5=0; U_45_6=0

check_ubuntu_mail() {
    local pkg=$1
    local f_exist=$2
    local f_ver=$3

    # 패키지 설치 여부 또는 프로세스 확인
    if dpkg -l | grep -qw "$pkg" || ps -ef | grep -v grep | grep -qw "$pkg"; then
        declare -g "$f_exist=1"
        # 업데이트 가능 목록에 있는지 확인 (버전 미흡 판단)
        if apt list --upgradable 2>/dev/null | grep -qw "$pkg"; then
            declare -g "$f_ver=1"
        fi
    fi
}

check_ubuntu_mail "sendmail" "U_45_1" "U_45_2"
check_ubuntu_mail "postfix"  "U_45_3" "U_45_4"
check_ubuntu_mail "exim4"    "U_45_5" "U_45_6"

IS_VUL=0
[ "$U_45_2" -eq 1 ] || [ "$U_45_4" -eq 1 ] || [ "$U_45_6" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { 
        "U_45_1": $U_45_1, "U_45_2": $U_45_2, 
        "U_45_3": $U_45_3, "U_45_4": $U_45_4, 
        "U_45_5": $U_45_5, "U_45_6": $U_45_6 
    },
    "timestamp": "$DATE"
  }
}
EOF