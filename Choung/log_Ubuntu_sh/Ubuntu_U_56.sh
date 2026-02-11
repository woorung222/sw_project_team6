#!/bin/bash

# [U-56] FTP 서비스에 비인가자의 접근 가능 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-56"
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
U_56_1=0; U_56_2=0; U_56_3=0; U_56_4=0; U_56_5=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_56_1] FTP - ftpusers 점검
if [[ -f "/etc/ftpusers" ]]; then
    STAT_INFO=$(run_cmd "[U_56_1] /etc/ftpusers 권한 확인" "stat -c '%U %a' /etc/ftpusers")
    OWNER=$(echo "$STAT_INFO" | awk '{print $1}')
    PERM=$(echo "$STAT_INFO" | awk '{print $2}')
    
    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
        U_56_1=1
        log_basis "[U_56_1] /etc/ftpusers 소유자($OWNER) 또는 권한($PERM) 취약" "취약"
    else
        log_basis "[U_56_1] /etc/ftpusers 권한 양호 ($STAT_INFO)" "양호"
    fi
else
    TMP=$(run_cmd "[U_56_1] 파일 확인" "ls /etc/ftpusers 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_56_1] /etc/ftpusers 파일 없음" "양호"
fi

# 2. [U_56_2] vsFTP - ftpusers 점검
VS_FTPUSERS=""
if [[ -f "/etc/vsftpd.ftpusers" ]]; then VS_FTPUSERS="/etc/vsftpd.ftpusers";
elif [[ -f "/etc/vsftpd/ftpusers" ]]; then VS_FTPUSERS="/etc/vsftpd/ftpusers"; fi

if [[ -n "$VS_FTPUSERS" ]]; then
    STAT_INFO=$(run_cmd "[U_56_2] $VS_FTPUSERS 권한 확인" "stat -c '%U %a' \"$VS_FTPUSERS\"")
    OWNER=$(echo "$STAT_INFO" | awk '{print $1}')
    PERM=$(echo "$STAT_INFO" | awk '{print $2}')
    
    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
        U_56_2=1
        log_basis "[U_56_2] $VS_FTPUSERS 소유자($OWNER) 또는 권한($PERM) 취약" "취약"
    else
        log_basis "[U_56_2] $VS_FTPUSERS 권한 양호 ($STAT_INFO)" "양호"
    fi
else
    TMP=$(run_cmd "[U_56_2] vsFTP ftpusers 파일 확인" "ls /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_56_2] vsFTP용 ftpusers 파일 미존재" "양호"
fi

# 3. [U_56_3] vsFTP - user_list 점검
VS_USERLIST=""
if [[ -f "/etc/vsftpd.user_list" ]]; then VS_USERLIST="/etc/vsftpd.user_list";
elif [[ -f "/etc/vsftpd/user_list" ]]; then VS_USERLIST="/etc/vsftpd/user_list"; fi

if [[ -n "$VS_USERLIST" ]]; then
    STAT_INFO=$(run_cmd "[U_56_3] $VS_USERLIST 권한 확인" "stat -c '%U %a' \"$VS_USERLIST\"")
    OWNER=$(echo "$STAT_INFO" | awk '{print $1}')
    PERM=$(echo "$STAT_INFO" | awk '{print $2}')
    
    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
        U_56_3=1
        log_basis "[U_56_3] $VS_USERLIST 소유자($OWNER) 또는 권한($PERM) 취약" "취약"
    else
        log_basis "[U_56_3] $VS_USERLIST 권한 양호 ($STAT_INFO)" "양호"
    fi
else
    TMP=$(run_cmd "[U_56_3] vsFTP user_list 파일 확인" "ls /etc/vsftpd.user_list /etc/vsftpd/user_list 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_56_3] vsFTP용 user_list 파일 미존재" "양호"
fi

# 4. [U_56_4] ProFTP - ftpusers 점검
if [[ -f "/etc/ftpd/ftpusers" ]]; then
    STAT_INFO=$(run_cmd "[U_56_4] /etc/ftpd/ftpusers 권한 확인" "stat -c '%U %a' /etc/ftpd/ftpusers")
    OWNER=$(echo "$STAT_INFO" | awk '{print $1}')
    PERM=$(echo "$STAT_INFO" | awk '{print $2}')
    
    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
        U_56_4=1
        log_basis "[U_56_4] /etc/ftpd/ftpusers 소유자($OWNER) 또는 권한($PERM) 취약" "취약"
    else
        log_basis "[U_56_4] /etc/ftpd/ftpusers 권한 양호 ($STAT_INFO)" "양호"
    fi
else
    TMP=$(run_cmd "[U_56_4] ProFTP ftpusers 파일 확인" "ls /etc/ftpd/ftpusers 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_56_4] /etc/ftpd/ftpusers 파일 미존재" "양호"
fi

# 5. [U_56_5] ProFTP - proftpd.conf 점검
PROFTP_CONF=""
if [[ -f "/etc/proftpd/proftpd.conf" ]]; then PROFTP_CONF="/etc/proftpd/proftpd.conf";
elif [[ -f "/etc/proftpd.conf" ]]; then PROFTP_CONF="/etc/proftpd.conf"; fi

if [[ -n "$PROFTP_CONF" ]]; then
    STAT_INFO=$(run_cmd "[U_56_5] $PROFTP_CONF 권한 확인" "stat -c '%U %a' \"$PROFTP_CONF\"")
    OWNER=$(echo "$STAT_INFO" | awk '{print $1}')
    PERM=$(echo "$STAT_INFO" | awk '{print $2}')
    
    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
        U_56_5=1
        log_basis "[U_56_5] $PROFTP_CONF 소유자($OWNER) 또는 권한($PERM) 취약" "취약"
    else
        log_basis "[U_56_5] $PROFTP_CONF 권한 양호 ($STAT_INFO)" "양호"
    fi
else
    TMP=$(run_cmd "[U_56_5] ProFTP 설정 파일 확인" "ls /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_56_5] ProFTP 설정 파일 미존재" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_56_1 -eq 1 || $U_56_2 -eq 1 || $U_56_3 -eq 1 || $U_56_4 -eq 1 || $U_56_5 -eq 1 ]]; then
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
      "U_56_1": $U_56_1,
      "U_56_2": $U_56_2,
      "U_56_3": $U_56_3,
      "U_56_4": $U_56_4,
      "U_56_5": $U_56_5
    },
    "timestamp": "$DATE"
  }
}
EOF
