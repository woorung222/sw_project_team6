#!/bin/bash

# [U-47] 스팸 메일 릴레이 제한
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-47"
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
U_47_1=0; U_47_2=0; U_47_3=0; IS_VUL=0

# --- 점검 로직 시작 ---

# [47] 메일 서비스 통합 활성 확인 (로그 기록용)
M_ACT=$(run_cmd "[47] 메일 서비스(Sendmail, Postfix, Exim) 활성 상태 확인" "systemctl is-active sendmail postfix exim 2>/dev/null | grep 'active' || echo '안 깔려 있음'")

if [[ "$M_ACT" != "안 깔려 있음" ]]; then

    # 1. Sendmail 점검 (U_47_1)
    if systemctl is-active sendmail >/dev/null 2>&1; then
        RAW_VER=$(run_cmd "[U_47_1] Sendmail 버전 확인" "sendmail -d0.1 < /dev/null 2>&1 | grep 'Version'")
        VER_NUM=$(echo "$RAW_VER" | awk '{print $2}')
        MAJOR=$(echo "$VER_NUM" | cut -d. -f1 | tr -cd '0-9'); MINOR=$(echo "$VER_NUM" | cut -d. -f2 | tr -cd '0-9')
        
        if [[ "${MAJOR:-0}" -gt 8 ]] || [[ "${MAJOR:-0}" -eq 8 && "${MINOR:-0}" -ge 9 ]]; then
            S_REL=$(run_cmd "[U_47_1] Sendmail 릴레이 설정 확인" "grep -v '^#' /etc/mail/sendmail.cf 2>/dev/null | grep -i 'promiscuous_relay' || ls /etc/mail/access.db 2>/dev/null || echo 'access.db_없음'")
            if [[ "$S_REL" == *"promiscuous_relay"* ]] || [[ "$S_REL" == "access.db_없음" ]]; then 
                U_47_1=1
                log_basis "[U_47_1] Sendmail 릴레이 제한 설정 미흡" "취약"
            else
                log_basis "[U_47_1] Sendmail 릴레이 설정 양호" "양호"
            fi
        else
            S_OLD=$(run_cmd "[U_47_1] Sendmail 구버전 릴레이 거부 규칙 확인" "grep -v '^#' /etc/mail/sendmail.cf 2>/dev/null | grep 'Relaying denied' || echo '누락'")
            if [[ "$S_OLD" == "누락" ]]; then 
                U_47_1=1
                log_basis "[U_47_1] 구버전 Sendmail 릴레이 거부 규칙 누락" "취약"
            else
                log_basis "[U_47_1] 구버전 Sendmail 릴레이 설정 양호" "양호"
            fi
        fi
    else
        log_basis "[U_47_1] Sendmail 서비스가 활성화되어 있지 않음 (안 깔려 있음)" "양호"
    fi

    # 2. Postfix 점검 (U_47_2)
    if systemctl is-active postfix >/dev/null 2>&1; then
        P_REL=$(run_cmd "[U_47_2] Postfix mynetworks 정책 확인" "postconf -n mynetworks 2>/dev/null")
        if [[ "$P_REL" == *"0.0.0.0/0"* ]] || [[ "$P_REL" == *"*"* ]]; then 
            U_47_2=1
            log_basis "[U_47_2] Postfix Open Relay 설정 발견" "취약"
        else
            log_basis "[U_47_2] Postfix 릴레이 설정 양호" "양호"
        fi
    else
        log_basis "[U_47_2] Postfix 서비스가 활성화되어 있지 않음 (안 깔려 있음)" "양호"
    fi

    # 3. Exim 점검 (U_47_3)
    if systemctl is-active exim >/dev/null 2>&1; then
        E_CONF=$(run_cmd "[U_47_3] Exim 설정 파일 확인" "exim -bV 2>/dev/null | grep 'Configuration file' | awk '{print \$3}'")
        if [[ -f "$E_CONF" ]]; then
            E_REL=$(run_cmd "[U_47_3] Exim 릴레이 허용 확인" "grep -E 'relay_from_hosts|accept hosts' '$E_CONF' 2>/dev/null | grep -v '^#' | grep '*' || echo '안전'")
            if [[ "$E_REL" != "안전" ]]; then 
                U_47_3=1
                log_basis "[U_47_3] Exim 릴레이 제한 설정 미흡" "취약"
            else
                log_basis "[U_47_3] Exim 릴레이 설정 양호" "양호"
            fi
        fi
    else
        log_basis "[U_47_3] Exim 서비스가 활성화되어 있지 않음 (안 깔려 있음)" "양호"
    fi
else
    log_basis "[U_47_1] 메일 서비스 미사용 (안 깔려 있음)" "양호"
    log_basis "[U_47_2] 메일 서비스 미사용 (안 깔려 있음)" "양호"
    log_basis "[U_47_3] 메일 서비스 미사용 (안 깔려 있음)" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_47_1 -eq 1 || $U_47_2 -eq 1 || $U_47_3 -eq 1 ]]; then IS_VUL=1; fi

# JSON 출력
cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_47_1": $U_47_1,
      "U_47_2": $U_47_2,
      "U_47_3": $U_47_3
    },
    "timestamp": "$DATE"
  }
}
EOF