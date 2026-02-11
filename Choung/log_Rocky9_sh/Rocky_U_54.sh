#!/bin/bash

# [U-54] 암호화되지 않은 FTP 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-54"
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
U_54_1=0; U_54_2=0; U_54_3=0; U_54_4=0; U_54_5=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. 패키지 설치 여부 확인 (로그 기록용)
FTP_PKGS=$(run_cmd "[54] FTP 관련 패키지(vsftpd, proftpd) 설치 확인" "rpm -qa | grep -qE 'vsftpd|proftpd' && echo '설치됨' || echo '안 깔려 있음'")

if [[ "$FTP_PKGS" == "설치됨" ]]; then
    # 2. [U_54_1] inetd 설정 점검
    if [[ -f "/etc/inetd.conf" ]]; then
        I_RES=$(run_cmd "[U_54_1] inetd ftp 설정 확인" "grep -v '^#' /etc/inetd.conf | grep 'ftp' || echo '미설정'")
        if [[ "$I_RES" != "미설정" ]]; then 
            U_54_1=1
            log_basis "[U_54_1] inetd 설정 내 FTP 서비스가 활성화되어 취약함" "취약"
        else
            log_basis "[U_54_1] inetd 설정 내 FTP 서비스가 발견되지 않아 양호함" "양호"
        fi
    else
        log_step "[U_54_1] 파일 확인" "ls /etc/inetd.conf" "파일 없음"
        log_basis "[U_54_1] inetd 설정 파일이 존재하지 않아 양호함" "양호"
    fi

    # 3. [U_54_2] xinetd 설정 점검
    if [[ -f "/etc/xinetd.d/ftp" ]]; then
        X_RES=$(run_cmd "[U_54_2] xinetd ftp 설정 확인" "grep 'disable' /etc/xinetd.d/ftp | grep 'yes' || echo '취약'")
        if [[ "$X_RES" == "취약" ]]; then 
            U_54_2=1
            log_basis "[U_54_2] xinetd 설정 내 FTP 서비스가 활성화되어 취약함" "취약"
        else
            log_basis "[U_54_2] xinetd 설정 내 FTP 서비스가 비활성화되어 양호함" "양호"
        fi
    else
        log_step "[U_54_2] 파일 확인" "ls /etc/xinetd.d/ftp" "파일 없음"
        log_basis "[U_54_2] xinetd 내 FTP 설정 파일이 존재하지 않아 양호함" "양호"
    fi

    # 4. [U_54_3] vsFTP 서비스 점검 (Systemd)
    V_ACT=$(run_cmd "[U_54_3] vsftpd 서비스 활성 상태 확인" "systemctl is-active vsftpd 2>/dev/null || echo 'inactive'")
    if [[ "$V_ACT" == "active" ]]; then 
        U_54_3=1
        log_basis "[U_54_3] vsftpd 서비스가 활성화되어 취약함" "취약"
    else
        log_basis "[U_54_3] vsftpd 서비스가 비활성화 상태임" "양호"
    fi

    # 5. [U_54_4] ProFTP 서비스 점검 (Systemd)
    P_ACT=$(run_cmd "[U_54_4] proftpd 서비스 활성 상태 확인" "systemctl is-active proftpd 2>/dev/null || echo 'inactive'")
    if [[ "$P_ACT" == "active" ]]; then 
        U_54_4=1
        log_basis "[U_54_4] proftpd 서비스가 활성화되어 취약함" "취약"
    else
        log_basis "[U_54_4] proftpd 서비스가 비활성화 상태임" "양호"
    fi

    # 6. [U_54_5] 프로세스 점검
    PRC_RES=$(run_cmd "[U_54_5] FTP 프로세스 실행 여부 확인" "ps -ef | grep -v grep | grep -qE 'vsftpd|proftpd|ftpd' && echo '실행 중' || echo '미실행'")
    if [[ "$PRC_RES" == "실행 중" ]]; then 
        U_54_5=1
        log_basis "[U_54_5] 암호화되지 않은 FTP 프로세스가 실행 중으로 취약함" "취약"
    else
        log_basis "[U_54_5] 실행 중인 FTP 프로세스가 발견되지 않음" "양호"
    fi
else
    # 패키지가 설치되어 있지 않은 경우 모든 플래그에 대해 "안 깔려 있음" 기록
    log_basis "[U_54_1] FTP 관련 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
    log_basis "[U_54_2] FTP 관련 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
    log_basis "[U_54_3] FTP 관련 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
    log_basis "[U_54_4] FTP 관련 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
    log_basis "[U_54_5] FTP 관련 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

# 최종 취약 여부 판단 (하나라도 1이면 취약)
if [[ $U_54_1 -eq 1 ]] || [[ $U_54_2 -eq 1 ]] || [[ $U_54_3 -eq 1 ]] || [[ $U_54_4 -eq 1 ]] || [[ $U_54_5 -eq 1 ]]; then
    IS_VUL=1
fi

# 8. JSON 출력 (원본 구조 및 플래그 명칭 절대 유지)
cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-54",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_54_1": $U_54_1,
      "U_54_2": $U_54_2,
      "U_54_3": $U_54_3,
      "U_54_4": $U_54_4,
      "U_54_5": $U_54_5
    },
    "timestamp": "$DATE"
  }
}
EOF