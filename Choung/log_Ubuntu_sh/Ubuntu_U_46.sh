#!/bin/bash

# [U-46] SMTP 서비스 사용 시 일반 사용자의 옵션 제한 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-46"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then
    source "$BASE_DIR/common_logging.sh"
else
    echo "Warning: common_logging.sh not found." >&2
    run_cmd() { eval "$2"; }
    log_step() { :; }
    log_basis() { :; }
fi

# 2. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기화
U_46_1=0; U_46_2=0; U_46_3=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [U_46_1] Sendmail 점검
if [[ -f "/etc/mail/sendmail.cf" ]]; then
    RESTRICT_CHECK=$(run_cmd "[U_46_1] Sendmail 옵션 확인" "grep 'PrivacyOptions' /etc/mail/sendmail.cf | grep 'restrictqrun' || echo 'none'")
    
    if [[ "$RESTRICT_CHECK" == "none" ]]; then
        U_46_1=1
        log_basis "[U_46_1] Sendmail 설정에 restrictqrun 옵션이 없음" "취약"
    else
        log_basis "[U_46_1] Sendmail restrictqrun 옵션 설정됨" "양호"
    fi
else
    TMP=$(run_cmd "[U_46_1] Sendmail 설정 파일 확인" "ls /etc/mail/sendmail.cf 2>/dev/null || echo '없음'")
    log_basis "[U_46_1] Sendmail 설정 파일(/etc/mail/sendmail.cf) 미존재" "양호"
fi

# 2. [U_46_2] Postfix 점검
POSTSUPER_CMD=$(run_cmd "[U_46_2] postsuper 명령 위치" "command -v postsuper || echo 'none'")

if [[ "$POSTSUPER_CMD" != "none" ]]; then
    # 일반 사용자(others) 실행 권한 확인 (10번째 문자)
    POSTSUPER_PERM=$(run_cmd "[U_46_2] postsuper 권한 확인" "stat -c '%A' \"$POSTSUPER_CMD\" 2>/dev/null | cut -c 10")
    
    if [[ "$POSTSUPER_PERM" != "-" ]]; then
        U_46_2=1
        log_basis "[U_46_2] postsuper 명령어에 일반 사용자 실행 권한($POSTSUPER_PERM) 존재" "취약"
    else
        log_basis "[U_46_2] postsuper 명령어 일반 사용자 실행 권한 제한됨" "양호"
    fi
else
    log_basis "[U_46_2] postsuper 명령어 미발견 (Postfix 미사용 추정)" "양호"
fi

# 3. [U_46_3] Exim 점검
EXIQGREP_CMD=$(run_cmd "[U_46_3] exiqgrep 명령 위치" "command -v exiqgrep || echo 'none'")

if [[ "$EXIQGREP_CMD" != "none" ]]; then
    EXIQGREP_PERM=$(run_cmd "[U_46_3] exiqgrep 권한 확인" "stat -c '%A' \"$EXIQGREP_CMD\" 2>/dev/null | cut -c 10")
    
    if [[ "$EXIQGREP_PERM" != "-" ]]; then
        U_46_3=1
        log_basis "[U_46_3] exiqgrep 명령어에 일반 사용자 실행 권한($EXIQGREP_PERM) 존재" "취약"
    else
        log_basis "[U_46_3] exiqgrep 명령어 일반 사용자 실행 권한 제한됨" "양호"
    fi
else
    log_basis "[U_46_3] exiqgrep 명령어 미발견 (Exim 미사용 추정)" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_46_1 -eq 1 || $U_46_2 -eq 1 || $U_46_3 -eq 1 ]]; then
    IS_VUL=1
fi

# JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_46_1": $U_46_1,
      "U_46_2": $U_46_2,
      "U_46_3": $U_46_3
    },
    "timestamp": "$DATE"
  }
}
EOF
