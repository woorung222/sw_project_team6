#!/bin/bash

# [U-45] 취약한 버전의 메일 서비스 이용 여부 점검 (Sendmail, Postfix, Exim)
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-45"
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

# 3. 점검 변수 초기화 (원본 코드 기준)
# 원본 로직: 설치되어 있으면 0(정보성), 미설치인데 활성화면 1(취약)
U_45_1=0
U_45_2=0
U_45_3=0
U_45_4=0
U_45_5=0
U_45_6=0
IS_VUL=0

# --- 점검 로직 수행 ---

# [1. Sendmail 점검]
# 원본: command -v sendmail 존재 여부 확인
CHECK_SENDMAIL_CMD=$(run_cmd "[U_45_1] Sendmail 명령어 확인" "command -v sendmail || echo 'none'")

if [[ "$CHECK_SENDMAIL_CMD" != "none" ]]; then
    # 사용하는 경우 (원본 로직: 버전 정보만 로깅하고 U_45_1=0 유지)
    SENDMAIL_VER=$(run_cmd "[U_45_1] Sendmail 버전 확인" "sendmail -d0.1 -bt < /dev/null 2>&1 | grep 'Version' || echo 'Version check failed'")
    
    # 원본 로직 준수: 설치되어 있어도 0 (취약 아님, 정보성)
    U_45_1=0
    log_basis "[U_45_1] Sendmail 서비스 설치됨 (버전: $SENDMAIL_VER)" "양호"
else
    # 사용하지 않는 경우 (서비스 활성화 여부 확인)
    SENDMAIL_ACT=$(run_cmd "[U_45_2] Sendmail 서비스 상태 확인" "systemctl list-units --type=service 2>/dev/null | grep sendmail || echo 'none'")
    
    if [[ "$SENDMAIL_ACT" != "none" ]]; then
        U_45_2=1
        log_basis "[U_45_2] Sendmail 미설치 환경이나 서비스(systemd)가 활성화됨" "취약"
    else
        log_basis "[U_45_2] Sendmail 미설치 및 서비스 비활성화" "양호"
    fi
fi

# [2. Postfix 점검]
# 원본: command -v postconf 존재 여부 확인
CHECK_POSTFIX_CMD=$(run_cmd "[U_45_3] Postfix 명령어 확인" "command -v postconf || echo 'none'")

if [[ "$CHECK_POSTFIX_CMD" != "none" ]]; then
    # 사용하는 경우 (원본 로직: 버전 로깅, U_45_3=0)
    POSTFIX_VER=$(run_cmd "[U_45_3] Postfix 버전 확인" "postconf -d mail_version 2>/dev/null || echo 'Unknown'")
    
    U_45_3=0
    log_basis "[U_45_3] Postfix 서비스 설치됨 (버전: $POSTFIX_VER)" "양호"
else
    # 사용하지 않는 경우 (프로세스 확인)
    POSTFIX_PS=$(run_cmd "[U_45_4] Postfix 프로세스 확인" "ps -ef | grep postfix | grep -v 'grep' || echo 'none'")
    
    if [[ "$POSTFIX_PS" != "none" ]]; then
        U_45_4=1
        log_basis "[U_45_4] Postfix 미설치 환경이나 프로세스 구동 중" "취약"
    else
        log_basis "[U_45_4] Postfix 미설치 및 프로세스 미구동" "양호"
    fi
fi

# [3. Exim 점검]
# 원본: command -v exim 존재 여부 확인
CHECK_EXIM_CMD=$(run_cmd "[U_45_5] Exim 명령어 확인" "command -v exim || echo 'none'")

if [[ "$CHECK_EXIM_CMD" != "none" ]]; then
    # 사용하는 경우 (원본 로직: 서비스 확인하지만 변수 할당은 0)
    EXIM_ACT=$(run_cmd "[U_45_5] Exim 서비스 상태" "systemctl list-units --type=service 2>/dev/null | grep exim || echo 'none'")
    
    U_45_5=0
    log_basis "[U_45_5] Exim 서비스 설치됨" "양호"
else
    # 사용하지 않는 경우 (프로세스 확인)
    EXIM_PS=$(run_cmd "[U_45_6] Exim 프로세스 확인" "ps -ef | grep exim | grep -v 'grep' || echo 'none'")
    
    if [[ "$EXIM_PS" != "none" ]]; then
        U_45_6=1
        log_basis "[U_45_6] Exim 미설치 환경이나 프로세스 구동 중" "취약"
    else
        log_basis "[U_45_6] Exim 미설치 및 프로세스 미구동" "양호"
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
# 원본 로직 유지: 2, 4, 6번 플래그 중 하나라도 1이면 취약
if [[ "$U_45_2" -eq 1 ]] || [[ "$U_45_4" -eq 1 ]] || [[ "$U_45_6" -eq 1 ]]; then
    IS_VUL=1
fi

# --- 5. JSON 출력 (Stdout) ---
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
      "U_45_1": $U_45_1,
      "U_45_2": $U_45_2,
      "U_45_3": $U_45_3,
      "U_45_4": $U_45_4,
      "U_45_5": $U_45_5,
      "U_45_6": $U_45_6
    },
    "timestamp": "$DATE"
  }
}
EOF