#!/bin/bash

# [U-57] ftpusers 파일 설정
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-57"
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
U_57_1=0; U_57_2=0; U_57_3=0; U_57_4=0; U_57_5=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [Common] 기본 FTP-ftpusers 점검 (U_57_1)
COMMON_FTPUSERS=$(run_cmd "[U_57_1] 공통 ftpusers 파일 확인" "ls /etc/ftpusers /etc/ftpd/ftpusers 2>/dev/null | head -1 || echo '없음'")

if [[ "$COMMON_FTPUSERS" != "없음" ]]; then
    # root 계정이 포함되어 있는지 확인 (주석 제외)
    if ! run_cmd "[U_57_1] $COMMON_FTPUSERS 내 root 계정 포함 여부 확인" "grep -v '^#' '$COMMON_FTPUSERS' | grep -qw 'root'"; then
        U_57_1=1
        log_basis "[U_57_1] $COMMON_FTPUSERS 파일 내 root 계정이 제한되어 있지 않음" "취약"
    else
        log_basis "[U_57_1] $COMMON_FTPUSERS 파일 내 root 계정이 적절히 제한됨" "양호"
    fi
else
    log_basis "[U_57_1] 공통 ftpusers 파일이 존재하지 않음 (양호)" "양호"
fi

# vsftpd 및 proftpd 패키지 설치 여부 확인 (내부 변수)
PKG_V=$(rpm -qa vsftpd)
PKG_P=$(rpm -qa proftpd)

# 2. [vsFTP] 점검 (U_57_2, U_57_3)
if [[ -n "$PKG_V" ]]; then
    # 2-1. vsFTP - ftpusers 점검 (U_57_2)
    VS_FTPUSERS=$(run_cmd "[U_57_2] vsftpd 전용 ftpusers 파일 확인" "ls /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers 2>/dev/null | head -1 || echo '없음'")
    if [[ "$VS_FTPUSERS" != "없음" ]]; then
        if ! run_cmd "[U_57_2] $VS_FTPUSERS 내 root 포함 확인" "grep -v '^#' '$VS_FTPUSERS' | grep -qw 'root'"; then
            U_57_2=1
            log_basis "[U_57_2] $VS_FTPUSERS 파일 내 root 계정이 제한되어 있지 않음" "취약"
        else
            log_basis "[U_57_2] $VS_FTPUSERS 파일 내 root 계정이 적절히 제한됨" "양호"
        fi
    else
        log_basis "[U_57_2] vsftpd 전용 ftpusers 파일이 없음 (양호)" "양호"
    fi

    # 2-2. vsFTP - user_list 점검 (U_57_3)
    VS_USERLIST=$(run_cmd "[U_57_3] vsftpd user_list 파일 확인" "ls /etc/vsftpd/user_list /etc/vsftpd.user_list 2>/dev/null | head -1 || echo '없음'")
    if [[ "$VS_USERLIST" != "없음" ]]; then
        if ! run_cmd "[U_57_3] $VS_USERLIST 내 root 포함 확인" "grep -v '^#' '$VS_USERLIST' | grep -qw 'root'"; then
            U_57_3=1
            log_basis "[U_57_3] $VS_USERLIST 파일 내 root 계정이 제한되어 있지 않음" "취약"
        else
            log_basis "[U_57_3] $VS_USERLIST 파일 내 root 계정이 적절히 제한됨" "양호"
        fi
    else
        log_basis "[U_57_3] vsftpd user_list 파일이 없음 (양호)" "양호"
    fi
else
    log_basis "[U_57_2] vsftpd 서비스 미설치 (안 깔려 있음)" "양호"
    log_basis "[U_57_3] vsftpd 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 3. [ProFTP] 점검 (U_57_4, U_57_5)
if [[ -n "$PKG_P" ]]; then
    # 3-1. ProFTP - ftpusers 점검 (U_57_4)
    PRO_FTPUSERS=$(run_cmd "[U_57_4] ProFTP 전용 ftpusers 파일 확인" "ls /etc/ftpd/ftpusers 2>/dev/null || echo '없음'")
    if [[ "$PRO_FTPUSERS" != "없음" ]]; then
        if ! run_cmd "[U_57_4] $PRO_FTPUSERS 내 root 포함 확인" "grep -v '^#' '$PRO_FTPUSERS' | grep -qw 'root'"; then
            U_57_4=1
            log_basis "[U_57_4] $PRO_FTPUSERS 파일 내 root 계정이 제한되어 있지 않음" "취약"
        else
            log_basis "[U_57_4] $PRO_FTPUSERS 파일 내 root 계정이 적절히 제한됨" "양호"
        fi
    else
        log_basis "[U_57_4] ProFTP 전용 ftpusers 파일이 없음 (양호)" "양호"
    fi

    # 3-2. ProFTP - RootLogin 설정 점검 (U_57_5)
    PROFTP_CONF=$(run_cmd "[U_57_5] ProFTP 설정 파일 확인" "ls /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null | head -1 || echo '없음'")
    if [[ "$PROFTP_CONF" != "없음" ]]; then
        if ! run_cmd "[U_57_5] RootLogin off 설정 여부 확인" "grep -v '^#' '$PROFTP_CONF' | grep -i 'RootLogin' | grep -iq 'off'"; then
            U_57_5=1
            log_basis "[U_57_5] ProFTP 설정 내 RootLogin off 설정이 미흡함" "취약"
        else
            log_basis "[U_57_5] ProFTP 설정 내 RootLogin off 설정이 존재함" "양호"
        fi
    else
        log_basis "[U_57_5] ProFTP 설정 파일이 없음 (양호)" "양호"
    fi
else
    log_basis "[U_57_4] proftpd 서비스 미설치 (안 깔려 있음)" "양호"
    log_basis "[U_57_5] proftpd 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 4. 전체 취약 여부 판단 (하나라도 1이면 취약)
if [[ $U_57_1 -eq 1 ]] || [[ $U_57_2 -eq 1 ]] || [[ $U_57_3 -eq 1 ]] || [[ $U_57_4 -eq 1 ]] || [[ $U_57_5 -eq 1 ]]; then
    IS_VUL=1
fi

# 5. JSON 출력 (원본 구조 및 플래그 명칭 절대 유지)
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
      "U_57_1": $U_57_1,
      "U_57_2": $U_57_2,
      "U_57_3": $U_57_3,
      "U_57_4": $U_57_4,
      "U_57_5": $U_57_5
    },
    "timestamp": "$DATE"
  }
}
EOF
