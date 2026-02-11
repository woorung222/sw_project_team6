#!/bin/bash

# [U-53] FTP 서비스 정보 노출 제한
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-53"
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
U_53_1=0; U_53_2=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [vsFTP] 점검 (U_53_1)
V_INST=$(run_cmd "[U_53_1] vsftpd 패키지 설치 확인" "rpm -qa vsftpd || echo '안 깔려 있음'")
if [[ "$V_INST" != "안 깔려 있음" ]]; then
    CONF="/etc/vsftpd/vsftpd.conf"
    [[ ! -f "$CONF" ]] && CONF="/etc/vsftpd.conf"
    
    if [[ -f "$CONF" ]]; then
        V_BAN=$(run_cmd "[U_53_1] vsftpd 배너 설정(ftpd_banner) 확인" "grep -v '^#' '$CONF' | grep 'ftpd_banner' || echo '미설정'")
        if [[ "$V_BAN" == "미설정" ]]; then
            U_53_1=1
            log_basis "[U_53_1] vsftpd 배너 설정이 미흡하여 취약함" "취약"
        else
            log_basis "[U_53_1] vsftpd 배너 설정이 적절함" "양호"
        fi
    else
        log_step "[U_53_1] 설정 파일 확인" "ls $CONF" "파일 없음"
        U_53_1=1
        log_basis "[U_53_1] vsftpd 설정 파일이 없어 점검 불가(취약)" "취약"
    fi
else
    log_basis "[U_53_1] vsftpd 서비스가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

# 2. [ProFTP] 점검 (U_53_2)
P_INST=$(run_cmd "[U_53_2] proftpd 패키지 설치 확인" "rpm -qa proftpd || echo '안 깔려 있음'")
if [[ "$P_INST" != "안 깔려 있음" ]]; then
    CONF="/etc/proftpd/proftpd.conf"
    [[ ! -f "$CONF" ]] && CONF="/etc/proftpd.conf"
    
    if [[ -f "$CONF" ]]; then
        P_BAN=$(run_cmd "[U_53_2] proftpd 배너 설정(ServerIdent) 확인" "grep -v '^#' '$CONF' | grep 'ServerIdent' || echo '미설정'")
        if [[ "$P_BAN" == "미설정" ]]; then
            U_53_2=1
            log_basis "[U_53_2] proftpd 배너 설정이 미흡하여 취약함" "취약"
        else
            log_basis "[U_53_2] proftpd 배너 설정이 적절함" "양호"
        fi
    else
        log_step "[U_53_2] 설정 파일 확인" "ls $CONF" "파일 없음"
        U_53_2=1
        log_basis "[U_53_2] proftpd 설정 파일이 없어 점검 불가(취약)" "취약"
    fi
else
    log_basis "[U_53_2] proftpd 서비스가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_53_1 -eq 1 || $U_53_2 -eq 1 ]]; then IS_VUL=1; fi

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
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_53_1": $U_53_1,
      "U_53_2": $U_53_2
    },
    "timestamp": "$DATE"
  }
}
EOF