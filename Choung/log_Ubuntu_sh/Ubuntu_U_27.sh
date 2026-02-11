#!/bin/bash

# [U-27] $HOME/.rhosts, hosts.equiv 사용 금지
# 대상 운영체제 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-27"
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
U_27_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

SERVICE_ACTIVE=0

# 1. [U_27_1] 서비스 활성 여부 점검 (xinetd)
if [[ -d "/etc/xinetd.d" ]]; then
    R_XINETD=$(run_cmd "[U_27_1] xinetd 내 r-service 설정 확인" "grep -l 'disable.*=.*no' /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec 2>/dev/null || echo 'none'")
    if [[ "$R_XINETD" != "none" ]]; then SERVICE_ACTIVE=1; fi
else
    # 화면 노출 방지를 위해 변수에 할당
    TMP=$(run_cmd "[U_27_1] xinetd 디렉터리 확인" "ls -d /etc/xinetd.d 2>/dev/null || echo '없음'")
fi

# 2. [U_27_1] 서비스 활성 여부 점검 (inetd)
if [[ -f "/etc/inetd.conf" ]]; then
    R_INETD=$(run_cmd "[U_27_1] inetd.conf 내 r-service 설정 확인" "grep -E '^rlogin|^rsh|^rexec' /etc/inetd.conf 2>/dev/null || echo 'none'")
    if [[ "$R_INETD" != "none" ]]; then SERVICE_ACTIVE=1; fi
else
    TMP=$(run_cmd "[U_27_1] inetd.conf 파일 확인" "ls /etc/inetd.conf 2>/dev/null || echo '없음'")
fi

# 3. [U_27_1] 서비스 활성 여부 점검 (systemd)
R_SYSTEMD=$(run_cmd "[U_27_1] systemd r-service 활성 확인" "systemctl list-units --type=service --state=active | grep -E 'rsh|rlogin|rexec' || echo 'none'")
if [[ "$R_SYSTEMD" != "none" ]]; then SERVICE_ACTIVE=1; fi


# 4. [U_27_1] 파일 설정 점검
FILES_TO_CHECK=("/etc/hosts.equiv")
while IFS=: read -r uname uhome; do
    if [[ -d "$uhome" ]]; then
        FILES_TO_CHECK+=("$uhome/.rhosts")
    fi
done < <(awk -F: '$7!="/usr/sbin/nologin" && $7!="/bin/false" && $6!="" {print $1":"$6}' /etc/passwd)

VULN_FOUND=0
for f in "${FILES_TO_CHECK[@]}"; do
    if [[ -f "$f" ]]; then
        OWNER=$(run_cmd "[U_27_1] $f 소유자 확인" "stat -c '%U' '$f'")
        PERM=$(run_cmd "[U_27_1] $f 권한 확인" "stat -c '%a' '$f'")
        PLUS=$(run_cmd "[U_27_1] $f '+' 설정 확인" "grep '+' '$f' 2>/dev/null || echo 'clean'")
        
        # 취약 조건: root 소유 아님(hosts.equiv), 권한 > 600, '+' 설정 존재
        IS_VULN_FILE=0
        if [[ "$f" == "/etc/hosts.equiv" && "$OWNER" != "root" ]]; then IS_VULN_FILE=1; fi
        if [[ "$PERM" -gt 600 ]]; then IS_VULN_FILE=1; fi
        if [[ "$PLUS" != "clean" ]]; then IS_VULN_FILE=1; fi
        
        if [[ $IS_VULN_FILE -eq 1 ]]; then
            VULN_FOUND=1
            log_basis "[U_27_1] $f 파일 설정 미흡 (소유자:$OWNER, 권한:$PERM, +설정:$([[ $PLUS != 'clean' ]] && echo 'Y' || echo 'N'))" "취약"
        fi
    fi
done

# 최종 판정
if [[ $VULN_FOUND -eq 1 ]]; then
    U_27_1=1
    log_basis "[U_27_1] r-command 관련 설정 파일(.rhosts, hosts.equiv)이 취약하게 설정됨" "취약"
else
    if [[ $SERVICE_ACTIVE -eq 0 ]]; then
        log_basis "[U_27_1] r-command 서비스 비활성 및 관련 파일 양호" "양호"
    else
        log_basis "[U_27_1] 서비스 활성이지만 설정 파일 보안 양호" "양호"
    fi
fi

IS_VUL=$U_27_1

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
    "category": "file",
    "flag": {
      "U_27_1": $U_27_1
    },
    "timestamp": "$DATE"
  }
}
EOF