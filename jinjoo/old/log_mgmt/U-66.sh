#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : rsyslog 설정을 통한 주요 시스템 로그 기록 여부 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_66_1=0  # *.info
U_66_2=0  # auth,authpriv.*
U_66_3=0  # mail.*
U_66_4=0  # cron.*
U_66_5=0  # *.alert
U_66_6=0  # *.emerg

# 점검 대상 경로 정의
CONF_FILES="/etc/rsyslog.conf /etc/rsyslog.d/*.conf"
VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-66] 점검 시작: 정책에 따른 시스템 로깅 설정"

# [U_66_1] *.info 점검
if sudo grep -rE "\*\.info" $CONF_FILES 2>/dev/null | grep -v "^#" > /dev/null; then
    echo "▶ *.info 정책: [ 양호 ]"
    U_66_1=0
else
    echo "▶ *.info 정책: [ 취약 ]"
    U_66_1=1
    VULN_FLAGS="$VULN_FLAGS U_66_1"
fi

# [U_66_2] auth,authpriv.* 점검
if sudo grep -rE "(auth,authpriv\.\*|authpriv\.\*)" $CONF_FILES 2>/dev/null | grep -v "^#" > /dev/null; then
    echo "▶ 인증 로그 정책: [ 양호 ]"
    U_66_2=0
else
    echo "▶ 인증 로그 정책: [ 취약 ]"
    U_66_2=1
    VULN_FLAGS="$VULN_FLAGS U_66_2"
fi

# [U_66_3] mail.* 점검
if sudo grep -rE "mail\.\*" $CONF_FILES 2>/dev/null | grep -v "^#" > /dev/null; then
    echo "▶ mail.* 정책: [ 양호 ]"
    U_66_3=0
else
    echo "▶ mail.* 정책: [ 취약 ]"
    U_66_3=1
    VULN_FLAGS="$VULN_FLAGS U_66_3"
fi

# [U_66_4] cron.* 점검
if sudo grep -rE "cron\.\*" $CONF_FILES 2>/dev/null | grep -v "^#" > /dev/null; then
    echo "▶ cron.* 정책: [ 양호 ]"
    U_66_4=0
else
    echo "▶ cron.* 정책: [ 취약 ]"
    U_66_4=1
    VULN_FLAGS="$VULN_FLAGS U_66_4"
fi

# [U_66_5] *.alert 점검
if sudo grep -rE "\*\.alert" $CONF_FILES 2>/dev/null | grep -v "^#" > /dev/null; then
    echo "▶ *.alert 정책: [ 양호 ]"
    U_66_5=0
else
    echo "▶ *.alert 정책: [ 취약 ]"
    U_66_5=1
    VULN_FLAGS="$VULN_FLAGS U_66_5"
fi

# [U_66_6] *.emerg 점검
if sudo grep -rE "\*\.emerg" $CONF_FILES 2>/dev/null | grep -v "^#" > /dev/null; then
    echo "▶ *.emerg 정책: [ 양호 ]"
    U_66_6=0
else
    echo "▶ *.emerg 정책: [ 취약 ]"
    U_66_6=1
    VULN_FLAGS="$VULN_FLAGS U_66_6"
fi

echo "----------------------------------------------------"
echo "U_66_1 : $U_66_1"
echo "U_66_2 : $U_66_2"
echo "U_66_3 : $U_66_3"
echo "U_66_4 : $U_66_4"
echo "U_66_5 : $U_66_5"
echo "U_66_6 : $U_66_6"

# 최종 판정 및 취약 플래그 리스트 출력
if [[ $U_66_1 -eq 0 && $U_66_2 -eq 0 && $U_66_3 -eq 0 && $U_66_4 -eq 0 && $U_66_5 -eq 0 && $U_66_6 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    # xargs를 이용해 앞뒤 공백 제거 후 콤마(,) 등으로 치환 가능 (현재는 공백 구분)
    echo "▶ 미설정 로그 정책 플래그 리스트:$(echo $VULN_FLAGS | sed 's/ /, /g')"
fi

exit $FINAL_RESULT
