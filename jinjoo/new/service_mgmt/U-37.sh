#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : cron 및 at 관련 파일(명령어, 작업 목록, 설정 파일)의 소유자 및 권한 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_37_1 : cron 관련 (명령어, 작업 목록 파일, 관련 설정 파일)
# U_37_2 : at 관련 (명령어, 작업 목록 파일)
U_37_1=0
U_37_2=0

# --- 3. 점검 로직 수행 ---

# [U_37_1] cron 관련 파일 점검

# 1. crontab 명령어 실행 파일 점검 (/usr/bin/crontab)
if [ -f "/usr/bin/crontab" ]; then
    OWNER=$(stat -c "%U" /usr/bin/crontab)
    # Others 권한 확인 (stat -c "%A"의 10번째 문자: - 여야 함)
    PERM_OTHERS=$(stat -c "%A" /usr/bin/crontab | cut -c 10)
    
    if [[ "$OWNER" != "root" ]] || [[ "$PERM_OTHERS" != "-" ]]; then
        U_37_1=1
    fi
fi

# 2. cron 작업 목록 파일 (Spool) 점검 (/var/spool/cron/crontabs)
CRON_SPOOL="/var/spool/cron/crontabs"
if [ -d "$CRON_SPOOL" ]; then
    # 소유자 root가 아니거나, 권한이 640(rw-r-----) 보다 느슨한 파일 검색
    # (/027 -> Group Write(2) or Others rwx(7) is found)
    BAD_CRON_SPOOL=$(sudo find "$CRON_SPOOL" -type f \( ! -user root -o -perm /027 \) 2>/dev/null)
    if [ -n "$BAD_CRON_SPOOL" ]; then
        U_37_1=1
    fi
fi

# 3. /etc/ 내 cron 관련 설정 파일 점검
ETC_CRON_FILES=$(sudo find /etc -maxdepth 1 -name "cron*" 2>/dev/null)
for FILE in $ETC_CRON_FILES; do
    OWNER=$(stat -c "%U" "$FILE")
    PERM=$(stat -c "%a" "$FILE")
    # 소유자가 root가 아니거나 권한이 640 초과 시 취약
    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
        U_37_1=1
    fi
done


# [U_37_2] at 관련 파일 점검

# 1. at 명령어 실행 파일 점검 (/usr/bin/at)
if [ -f "/usr/bin/at" ]; then
    OWNER=$(stat -c "%U" /usr/bin/at)
    PERM_OTHERS=$(stat -c "%A" /usr/bin/at | cut -c 10)
    
    if [[ "$OWNER" != "root" ]] || [[ "$PERM_OTHERS" != "-" ]]; then
        U_37_2=1
    fi
fi

# 2. at 작업 목록 파일 (Spool) 점검 (/var/spool/cron/atjobs)
AT_SPOOL="/var/spool/cron/atjobs"
if [ -d "$AT_SPOOL" ]; then
    # 소유자 root가 아니거나 권한이 취약한 파일 검색
    BAD_AT_SPOOL=$(sudo find "$AT_SPOOL" -type f \( ! -user root -o -perm /027 \) 2>/dev/null)
    if [ -n "$BAD_AT_SPOOL" ]; then
        U_37_2=1
    fi
fi


# --- 4. 최종 취약 여부 판단 ---
if [ "$U_37_1" -eq 1 ] || [ "$U_37_2" -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- 5. JSON 출력 (Stdout) ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP_ADDR",
    "user": "$CURRENT_USER"
  },
  "result": {
    "flag_id": "U-37",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_37_1": $U_37_1,
      "U_37_2": $U_37_2
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
