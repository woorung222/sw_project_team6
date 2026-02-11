#!/bin/bash

# [U-01] root 계정의 원격터미널 접속 차단 설정
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-01"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then
    source "$BASE_DIR/common_logging.sh"
else
    # 모듈 없을 시 비상용 더미 함수 정의
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

# 초기 상태 설정
U_01_1=0
U_01_2=0
IS_VUL=0

# --- 점검 로직 시작 ---

# ---------------------------------------------------------
# 1. [U_01_1] Telnet 접속 제어 점검
# ---------------------------------------------------------
# Telnet 서비스 활성화 여부 확인
TELNET_CHECK_CMD="systemctl is-active telnet.socket telnet.service 2>/dev/null | grep -w 'active'"
TELNET_ACTIVE_RES=$(run_cmd "[U_01_1] Telnet 서비스 활성 상태 확인" "$TELNET_CHECK_CMD")

if [ -n "$TELNET_ACTIVE_RES" ]; then
    # Telnet이 활성화된 경우 추가 설정 점검
    
    # 1-1. /etc/pam.d/login 내 pam_securetty.so 설정 확인
    PAM_CMD="grep -v '^#' /etc/pam.d/login | grep 'pam_securetty.so'"
    PAM_CHECK=$(run_cmd "[U_01_1] pam_securetty.so 설정 확인" "$PAM_CMD")
    
    # 1-2. /etc/securetty 내 pts 설정 확인
    PTS_CMD="grep -v '^#' /etc/securetty | grep '^pts/'"
    if [ -f "/etc/securetty" ]; then
        PTS_CHECK=$(run_cmd "[U_01_1] /etc/securetty 내 pts 설정 확인" "$PTS_CMD")
    else
        log_step "[U_01_1] securetty 파일 점검" "[ -f /etc/securetty ]" "파일 없음 (안전)"
        PTS_CHECK=""
    fi

    # 판단: PAM 모듈이 없거나, securetty에 pts가 존재하면 취약
    if [ -z "$PAM_CHECK" ] || [ -n "$PTS_CHECK" ]; then
        U_01_1=1
        log_basis "[U_01_1] Telnet 사용 중이며 root 접속 제한 설정(pam_securetty, pts제한) 미흡" "취약"
    else
        U_01_1=0
        log_basis "[U_01_1] Telnet 사용 중이나 root 접속 제한 설정됨" "양호"
    fi
else
    # Telnet 서비스를 사용하지 않으므로 양호
    U_01_1=0
    log_basis "[U_01_1] Telnet 서비스가 비활성화 되어있음" "양호"
fi

# ---------------------------------------------------------
# 2. [U_01_2] SSH 접속 제어 점검
# ---------------------------------------------------------
SSHD_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONFIG" ]; then
    # PermitRootLogin 설정 확인 (대소문자 무시)
    SSH_CMD="grep -i '^PermitRootLogin' $SSHD_CONFIG | grep -v '^#' | awk '{print \$2}'"
    PERMIT_ROOT=$(run_cmd "[U_01_2] SSH PermitRootLogin 설정값 확인" "$SSH_CMD")

    # 값이 no(또는 No, NO)가 아니면 취약
    if [[ "$PERMIT_ROOT" =~ ^[Nn][Oo]$ ]]; then
        U_01_2=0
        log_basis "[U_01_2] SSH 설정 파일에서 Root 접속이 차단됨 (PermitRootLogin=no)" "양호"
    else
        U_01_2=1
        log_basis "[U_01_2] SSH Root 접속이 허용됨 또는 설정 미흡 (값: ${PERMIT_ROOT:-미설정})" "취약"
    fi
else
    U_01_2=1
    log_step "[U_01_2] SSH 설정 파일 점검" "[ -f $SSHD_CONFIG ]" "파일 없음"
    log_basis "[U_01_2] sshd_config 파일이 존재하지 않아 점검 불가" "취약"
fi

# ---------------------------------------------------------
# 3. 전체 결과 집계
# ---------------------------------------------------------
if [[ $U_01_1 -eq 1 ]] || [[ $U_01_2 -eq 1 ]]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# ---------------------------------------------------------
# 4. JSON 출력 (stdout)
# ---------------------------------------------------------
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
    "category": "account",
    "flag": {
      "U_01_1": $U_01_1,
      "U_01_2": $U_01_2
    },
    "timestamp": "$DATE"
  }
}
EOF
