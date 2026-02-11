#!/bin/bash

# [U-52] Telnet 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-52"
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

# 초기화 (0: 양호, 1: 취약)
U_52_1=0; U_52_2=0; U_52_3=0; U_52_4=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 서비스 설치 여부 사전 확인 (로그 기록용)
T_INST=$(run_cmd "[52] telnet-server 패키지 설치 확인" "rpm -qa telnet-server || echo '안 깔려 있음'")

if [[ "$T_INST" != "안 깔려 있음" ]]; then

    # 1. [U_52_1] inetd 설정 점검
    if [[ -f "/etc/inetd.conf" ]]; then
        I_RES=$(run_cmd "[U_52_1] inetd telnet 설정 확인" "grep -v '^#' /etc/inetd.conf | grep 'telnet' || echo '미설정'")
        if [[ "$I_RES" != "미설정" ]]; then 
            U_52_1=1
            log_basis "[U_52_1] inetd 설정 내 telnet 서비스가 활성화되어 취약함" "취약"
        else
            log_basis "[U_52_1] inetd 설정 내 telnet 서비스가 비활성화되어 양호함" "양호"
        fi
    else
        log_step "[U_52_1] 파일 확인" "ls /etc/inetd.conf" "파일 없음"
        log_basis "[U_52_1] inetd 설정 파일이 존재하지 않아 양호함" "양호"
    fi

    # 2. [U_52_2] xinetd 설정 점검
    if [[ -f "/etc/xinetd.d/telnet" ]]; then
        X_RES=$(run_cmd "[U_52_2] xinetd telnet 설정 확인" "grep 'disable' /etc/xinetd.d/telnet | grep 'yes' || echo '취약'")
        if [[ "$X_RES" == "취약" ]]; then 
            U_52_2=1
            log_basis "[U_52_2] xinetd 설정 내 telnet 서비스가 활성화되어 취약함" "취약"
        else
            log_basis "[U_52_2] xinetd 설정 내 telnet 서비스가 비활성화되어 양호함" "양호"
        fi
    else
        log_step "[U_52_2] 파일 확인" "ls /etc/xinetd.d/telnet" "파일 없음"
        log_basis "[U_52_2] xinetd 내 telnet 설정 파일이 존재하지 않아 양호함" "양호"
    fi

    # 3. [U_52_3] systemd 점검
    S_RES=$(run_cmd "[U_52_3] systemd telnet 서비스 활성 상태 확인" "systemctl is-active telnet.socket telnet.service 2>/dev/null | grep 'active' || echo 'inactive'")
    if [[ "$S_RES" == *"active"* ]]; then 
        U_52_3=1
        log_basis "[U_52_3] systemd를 통해 telnet 서비스가 활성화되어 취약함" "취약"
    else
        log_basis "[U_52_3] systemd 내 telnet 서비스가 비활성화 상태임" "양호"
    fi

    # 4. [U_52_4] Process 점검
    P_RES=$(run_cmd "[U_52_4] telnet 프로세스 실행 여부 확인" "ps -e -o comm | grep -xw 'telnetd' || echo '미실행'")
    if [[ "$P_RES" != "미실행" ]]; then 
        U_52_4=1
        log_basis "[U_52_4] telnet 서비스 프로세스가 현재 실행 중으로 취약함" "취약"
    else
        log_basis "[U_52_4] telnet 서비스 프로세스가 실행 중이지 않음" "양호"
    fi

else
    # 패키지가 설치되어 있지 않은 경우 모든 플래그에 대해 "안 깔려 있음" 기록
    log_basis "[U_52_1] telnet-server 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
    log_basis "[U_52_2] telnet-server 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
    log_basis "[U_52_3] telnet-server 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
    log_basis "[U_52_4] telnet-server 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

# 최종 취약 여부 판단 (하나라도 1이면 취약)
if [[ $U_52_1 -eq 1 || $U_52_2 -eq 1 || $U_52_3 -eq 1 || $U_52_4 -eq 1 ]]; then 
    IS_VUL=1
fi

# --- JSON 출력 (원본 구조 및 플래그 명칭 절대 유지) ---
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
      "U_52_1": $U_52_1,
      "U_52_2": $U_52_2,
      "U_52_3": $U_52_3,
      "U_52_4": $U_52_4
    },
    "timestamp": "$DATE"
  }
}
EOF