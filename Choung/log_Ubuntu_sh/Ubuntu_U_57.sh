#!/bin/bash

# [U-57] FTP 서비스에 root 계정 접근 제한 설정 여부 점검
# 대상 : Ubuntu 24.04

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

# 초기화
U_57_1=0; U_57_2=0; U_57_3=0; U_57_4=0; U_57_5=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_57_1] 기본 FTP-ftpusers 점검
FTPUSERS_FILE=""
if [[ -f "/etc/ftpusers" ]]; then FTPUSERS_FILE="/etc/ftpusers";
elif [[ -f "/etc/ftpd/ftpusers" ]]; then FTPUSERS_FILE="/etc/ftpd/ftpusers"; fi

if [[ -n "$FTPUSERS_FILE" ]]; then
    ROOT_CHECK=$(run_cmd "[U_57_1] $FTPUSERS_FILE 내 root 검색" "grep -x 'root' \"$FTPUSERS_FILE\" || echo 'none'")
    if [[ "$ROOT_CHECK" == "none" ]]; then
        U_57_1=1
        log_basis "[U_57_1] $FTPUSERS_FILE 내 root 계정이 등록되지 않음 (접근 허용)" "취약"
    else
        log_basis "[U_57_1] $FTPUSERS_FILE 내 root 계정 등록됨 (접근 제한)" "양호"
    fi
else
    TMP=$(run_cmd "[U_57_1] 기본 ftpusers 파일 확인" "ls /etc/ftpusers /etc/ftpd/ftpusers 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_57_1] 기본 ftpusers 파일 없음" "양호"
fi

# 2. [U_57_2] vsFTP - ftpusers 점검
VS_FTPUSERS=""
if [[ -f "/etc/vsftpd.ftpusers" ]]; then VS_FTPUSERS="/etc/vsftpd.ftpusers";
elif [[ -f "/etc/vsftpd/ftpusers" ]]; then VS_FTPUSERS="/etc/vsftpd/ftpusers"; fi

if [[ -n "$VS_FTPUSERS" ]]; then
    ROOT_CHECK=$(run_cmd "[U_57_2] $VS_FTPUSERS 내 root 검색" "grep -x 'root' \"$VS_FTPUSERS\" || echo 'none'")
    if [[ "$ROOT_CHECK" == "none" ]]; then
        U_57_2=1
        log_basis "[U_57_2] $VS_FTPUSERS 내 root 미등록" "취약"
    else
        log_basis "[U_57_2] $VS_FTPUSERS 내 root 등록됨" "양호"
    fi
else
    TMP=$(run_cmd "[U_57_2] vsFTP ftpusers 파일 확인" "ls /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_57_2] vsFTP용 ftpusers 파일 없음" "양호"
fi

# 3. [U_57_3] vsFTP - user_list 점검
VS_USERLIST=""
if [[ -f "/etc/vsftpd.user_list" ]]; then VS_USERLIST="/etc/vsftpd.user_list";
elif [[ -f "/etc/vsftpd/user_list" ]]; then VS_USERLIST="/etc/vsftpd/user_list"; fi

if [[ -n "$VS_USERLIST" ]]; then
    # user_list_deny=YES(기본) 전제
    ROOT_CHECK=$(run_cmd "[U_57_3] $VS_USERLIST 내 root 검색" "grep -x 'root' \"$VS_USERLIST\" || echo 'none'")
    if [[ "$ROOT_CHECK" == "none" ]]; then
        U_57_3=1
        log_basis "[U_57_3] $VS_USERLIST 내 root 미등록" "취약"
    else
        log_basis "[U_57_3] $VS_USERLIST 내 root 등록됨" "양호"
    fi
else
    TMP=$(run_cmd "[U_57_3] vsFTP user_list 파일 확인" "ls /etc/vsftpd.user_list /etc/vsftpd/user_list 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_57_3] vsFTP용 user_list 파일 없음" "양호"
fi

# 4. [U_57_4] ProFTP - ftpusers 점검
if [[ -f "/etc/ftpd/ftpusers" ]]; then
    ROOT_CHECK=$(run_cmd "[U_57_4] /etc/ftpd/ftpusers 내 root 검색" "grep -x 'root' /etc/ftpd/ftpusers || echo 'none'")
    if [[ "$ROOT_CHECK" == "none" ]]; then
        U_57_4=1
        log_basis "[U_57_4] /etc/ftpd/ftpusers 내 root 미등록" "취약"
    else
        log_basis "[U_57_4] /etc/ftpd/ftpusers 내 root 등록됨" "양호"
    fi
else
    TMP=$(run_cmd "[U_57_4] ProFTP ftpusers 파일 확인" "ls /etc/ftpd/ftpusers 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_57_4] ProFTP용 ftpusers 파일 없음" "양호"
fi

# 5. [U_57_5] ProFTP - proftpd.conf 점검
PROFTP_CONF=""
if [[ -f "/etc/proftpd/proftpd.conf" ]]; then PROFTP_CONF="/etc/proftpd/proftpd.conf";
elif [[ -f "/etc/proftpd.conf" ]]; then PROFTP_CONF="/etc/proftpd.conf"; fi

if [[ -n "$PROFTP_CONF" ]]; then
    ROOT_LOGIN_OFF=$(run_cmd "[U_57_5] RootLogin off 확인" "grep -i 'RootLogin' \"$PROFTP_CONF\" | grep -i 'off' | grep -v '^#' || echo 'none'")
    if [[ "$ROOT_LOGIN_OFF" == "none" ]]; then
        U_57_5=1
        log_basis "[U_57_5] ProFTP 설정 내 RootLogin off 미설정" "취약"
    else
        log_basis "[U_57_5] ProFTP RootLogin off 설정됨: $ROOT_LOGIN_OFF" "양호"
    fi
else
    TMP=$(run_cmd "[U_57_5] ProFTP 설정 파일 확인" "ls /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_57_5] ProFTP 설정 파일 없음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_57_1 -eq 1 || $U_57_2 -eq 1 || $U_57_3 -eq 1 || $U_57_4 -eq 1 || $U_57_5 -eq 1 ]]; then
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
