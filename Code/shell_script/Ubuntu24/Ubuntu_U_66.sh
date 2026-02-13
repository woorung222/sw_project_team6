#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 가이드 사례에 따른 시스템 로깅 설정 적정성 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_66_1 : [System] rsyslog 미설치 또는 서비스 비활성화
# U_66_2 : [Config] secure(authpriv) 로그 설정 미흡
# U_66_3 : [Config] messages(info) 로그 설정 미흡
# U_66_4 : [Config] cron 로그 설정 미흡
# U_66_5 : [Config] maillog(mail) 로그 설정 미흡

U_66_1=0
U_66_2=0
U_66_3=0
U_66_4=0
U_66_5=0

# --- 3. 점검 로직 수행 ---

# [U_66_1] rsyslog 설치 및 서비스 활성화 확인
if ! command -v rsyslogd >/dev/null 2>&1; then
    U_66_1=1
elif ! systemctl is-active --quiet rsyslog; then
    U_66_1=1
fi

# 설정 파일 경로 (/etc/rsyslog.conf 및 /etc/rsyslog.d/ 디렉토리)
CONF_FILES="/etc/rsyslog.conf /etc/rsyslog.d/"

# 설정 파일이 존재할 때만 내용 점검
if [ "$U_66_1" -eq 0 ]; then
    
    # [U_66_2] authpriv.* (보안/인증 로그) 설정 확인
    # 주석(#)으로 시작하지 않는 라인에서 authpriv.* 패턴 검색
    if ! grep -rE "authpriv\.\*" $CONF_FILES 2>/dev/null | grep -vE "^\s*#" >/dev/null; then
        U_66_2=1
    fi

    # [U_66_3] *.info (시스템 정보 로그) 설정 확인
    # 가이드 기준: *.info;mail.none;authpriv.none;cron.none 등
    # 핵심인 *.info 설정 여부를 중점으로 확인
    if ! grep -rE "\*\.info" $CONF_FILES 2>/dev/null | grep -vE "^\s*#" >/dev/null; then
        U_66_3=1
    fi

    # [U_66_4] cron.* (크론 로그) 설정 확인
    if ! grep -rE "cron\.\*" $CONF_FILES 2>/dev/null | grep -vE "^\s*#" >/dev/null; then
        U_66_4=1
    fi

    # [U_66_5] mail.* (메일 로그) 설정 확인
    if ! grep -rE "mail\.\*" $CONF_FILES 2>/dev/null | grep -vE "^\s*#" >/dev/null; then
        U_66_5=1
    fi

else
    # 서비스가 없으면 설정 점검도 불가하므로 모두 취약 처리
    U_66_2=1
    U_66_3=1
    U_66_4=1
    U_66_5=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_66_1" -eq 1 ] || [ "$U_66_2" -eq 1 ] || [ "$U_66_3" -eq 1 ] || [ "$U_66_4" -eq 1 ] || [ "$U_66_5" -eq 1 ]; then
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
    "flag_id": "U-66",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "log",
    "flag": {
      "U_66_1": $U_66_1,
      "U_66_2": $U_66_2,
      "U_66_3": $U_66_3,
      "U_66_4": $U_66_4,
      "U_66_5": $U_66_5
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
