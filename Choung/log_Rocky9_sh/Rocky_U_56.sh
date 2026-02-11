#!/bin/bash

# [U-56] FTP 서비스 접근 제어 설정
# 대상 운영체제 : Rocky Linux 9

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

# --- 점검 로직 시작 ---

# 1. [U_56_1] 공통 ftpusers 파일 점검
if [[ -f "/etc/ftpusers" ]]; then
    O_56_1=$(run_cmd "[U_56_1] /etc/ftpusers 소유자 확인" "stat -c '%U' /etc/ftpusers")
    P_56_1=$(run_cmd "[U_56_1] /etc/ftpusers 권한 확인" "stat -c '%a' /etc/ftpusers")
    if [[ "$O_56_1" != "root" ]] || [[ "$P_56_1" -gt 640 ]]; then
        U_56_1=1
        log_basis "[U_56_1] /etc/ftpusers 소유자($O_56_1) 또는 권한($P_56_1) 미흡" "취약"
    else
        log_basis "[U_56_1] /etc/ftpusers 설정 양호" "양호"
    fi
else
    log_step "[U_56_1] 파일 확인" "ls /etc/ftpusers" "파일 없음"
    log_basis "[U_56_1] /etc/ftpusers 파일이 존재하지 않음" "양호"
fi

# vsftpd 및 proftpd 패키지 설치 여부 확인 (내부 변수)
PKG_V=$(rpm -qa vsftpd)
PKG_P=$(rpm -qa proftpd)

# 2. [vsFTP] 점검 (U_56_2, U_56_3)
if [[ -n "$PKG_V" ]]; then
    V_CONF=$(run_cmd "[vsFTP] 설정 파일 확인" "ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null | head -1 || echo '없음'")
    if [[ "$V_CONF" != "없음" ]]; then
        U_ENABLE=$(run_cmd "[vsFTP] userlist_enable 설정 확인" "grep -v '^#' '$V_CONF' | grep 'userlist_enable' | awk -F= '{print \$2}' | tr -d ' ' | tr 'a-z' 'A-Z' || echo 'NO'")
        
        if [[ "$U_ENABLE" != "YES" ]]; then
            # [U_56_2] 점검
            if [[ -f "/etc/vsftpd/ftpusers" ]]; then
                VO_2=$(run_cmd "[U_56_2] /etc/vsftpd/ftpusers 소유자 확인" "stat -c '%U' /etc/vsftpd/ftpusers")
                VP_2=$(run_cmd "[U_56_2] /etc/vsftpd/ftpusers 권한 확인" "stat -c '%a' /etc/vsftpd/ftpusers")
                if [[ "$VO_2" != "root" ]] || [[ "$VP_2" -gt 640 ]]; then U_56_2=1; fi
            else U_56_2=1; fi
            log_basis "[U_56_2] vsftpd userlist_enable=NO 시 ftpusers 권한 확인" "$([[ $U_56_2 -eq 1 ]] && echo '취약' || echo '양호')"
            log_basis "[U_56_3] vsftpd userlist_enable=NO 상태로 해당 사항 없음" "양호"
        else
            # [U_56_3] 점검
            if [[ -f "/etc/vsftpd/user_list" ]]; then
                LO_3=$(run_cmd "[U_56_3] /etc/vsftpd/user_list 소유자 확인" "stat -c '%U' /etc/vsftpd/user_list")
                LP_3=$(run_cmd "[U_56_3] /etc/vsftpd/user_list 권한 확인" "stat -c '%a' /etc/vsftpd/user_list")
                if [[ "$LO_3" != "root" ]] || [[ "$LP_3" -gt 640 ]]; then U_56_3=1; fi
            else U_56_3=1; fi
            log_basis "[U_56_2] vsftpd userlist_enable=YES 상태로 해당 사항 없음" "양호"
            log_basis "[U_56_3] vsftpd userlist_enable=YES 시 user_list 권한 확인" "$([[ $U_56_3 -eq 1 ]] && echo '취약' || echo '양호')"
        fi
    else
        U_56_2=1
        log_basis "[U_56_2] vsftpd 설정 파일 미존재로 점검 불가" "취약"
    fi
else
    log_basis "[U_56_2] vsftpd 서비스 미설치 (안 깔려 있음)" "양호"
    log_basis "[U_56_3] vsftpd 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 3. [ProFTP] 점검 (U_56_4, U_56_5)
if [[ -n "$PKG_P" ]]; then
    P_CONF=$(run_cmd "[ProFTP] 설정 파일 확인" "ls /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null | head -1 || echo '없음'")
    if [[ "$P_CONF" != "없음" ]]; then
        USE_FTP=$(run_cmd "[ProFTP] UseFtpUsers 설정 확인" "grep -v '^#' '$P_CONF' | grep 'UseFtpUsers' | awk '{print \$2}' | tr 'a-z' 'A-Z' || echo 'ON'")
        
        if [[ "$USE_FTP" != "OFF" ]]; then
            if [[ -f "/etc/ftpusers" ]]; then
                PO_4=$(run_cmd "[U_56_4] ProFTP ftpusers 소유자 확인" "stat -c '%U' /etc/ftpusers")
                PP_4=$(run_cmd "[U_56_4] ProFTP ftpusers 권한 확인" "stat -c '%a' /etc/ftpusers")
                if [[ "$PO_4" != "root" ]] || [[ "$PP_4" -gt 640 ]]; then U_56_4=1; fi
            fi
            log_basis "[U_56_4] ProFTP UseFtpUsers ON 시 ftpusers 권한 확인" "$([[ $U_56_4 -eq 1 ]] && echo '취약' || echo '양호')"
            log_basis "[U_56_5] ProFTP UseFtpUsers ON 상태로 해당 사항 없음" "양호"
        else
            CO_5=$(run_cmd "[U_56_5] ProFTP 설정파일($P_CONF) 소유자 확인" "stat -c '%U' '$P_CONF'")
            CP_5=$(run_cmd "[U_56_5] ProFTP 설정파일($P_CONF) 권한 확인" "stat -c '%a' '$P_CONF'")
            LM_5=$(run_cmd "[U_56_5] Limit LOGIN 블록 존재 확인" "grep -iq '<Limit LOGIN>' '$P_CONF' && echo '존재' || echo '없음'")
            if [[ "$CO_5" != "root" ]] || [[ "$CP_5" -gt 640 ]] || [[ "$LM_5" == "없음" ]]; then U_56_5=1; fi
            log_basis "[U_56_4] ProFTP UseFtpUsers OFF 상태로 해당 사항 없음" "양호"
            log_basis "[U_56_5] ProFTP UseFtpUsers OFF 시 설정파일 및 접근제한 확인" "$([[ $U_56_5 -eq 1 ]] && echo '취약' || echo '양호')"
        fi
    else
        U_56_4=1
        log_basis "[U_56_4] proftpd 설정 파일 미존재로 점검 불가" "취약"
    fi
else
    log_basis "[U_56_4] proftpd 서비스 미설치 (안 깔려 있음)" "양호"
    log_basis "[U_56_5] proftpd 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 4. 전체 취약 여부 판단
if [[ $U_56_1 -eq 1 ]] || [[ $U_56_2 -eq 1 ]] || [[ $U_56_3 -eq 1 ]] || [[ $U_56_4 -eq 1 ]] || [[ $U_56_5 -eq 1 ]]; then
    IS_VUL=1
fi

# 5. JSON 출력 (원본 구조 및 명칭 절대 유지)
cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-56",
    "is_vul": $IS_VUL,
    "is_auto": 0,
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