#!/bin/bash

# [U-65] 서버 시각 동기화 설정 및 가동 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-65"
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
U_65_1=0; U_65_2=0; U_65_3=0; IS_VUL=0

# --- 점검 로직 수행 ---

HAS_CHRONY=0
HAS_NTP=0
HAS_TIMESYNCD=0

# 1. 설치 여부 확인 (증빙 포함)
CHECK_CHRONY=$(run_cmd "[U_65] Chrony 설치 확인" "command -v chronyd || dpkg -l | grep chrony || echo 'none'")
if [[ "$CHECK_CHRONY" != "none" ]]; then HAS_CHRONY=1; fi

CHECK_NTP=$(run_cmd "[U_65] NTP 설치 확인" "command -v ntpd || dpkg -l | grep ntp || echo 'none'")
if [[ "$CHECK_NTP" != "none" ]]; then HAS_NTP=1; fi

CHECK_TIMESYNCD=$(run_cmd "[U_65] systemd-timesyncd 확인" "systemctl is-active systemd-timesyncd 2>/dev/null || echo 'inactive'")
if [[ "$CHECK_TIMESYNCD" == "active" ]]; then HAS_TIMESYNCD=1; fi


# [U_65_1] 시간 동기화 패키지 설치 여부
if [[ "$HAS_CHRONY" -eq 0 ]] && [[ "$HAS_NTP" -eq 0 ]] && [[ "$HAS_TIMESYNCD" -eq 0 ]]; then
    U_65_1=1
    log_basis "[U_65_1] 시간 동기화 관련 서비스/패키지가 전혀 없음" "취약"
else
    U_65_1=0
    log_basis "[U_65_1] 시간 동기화 서비스 설치됨 (Chrony:$HAS_CHRONY, NTP:$HAS_NTP, Timesyncd:$HAS_TIMESYNCD)" "양호"
fi


# [U_65_2] Chrony 설정 점검
if [[ "$HAS_CHRONY" -eq 1 ]]; then
    # 서비스 활성화 확인
    CHRONY_ACT=$(run_cmd "[U_65_2] Chrony 서비스 상태" "systemctl is-active chrony 2>/dev/null || echo 'inactive'")
    
    if [[ "$CHRONY_ACT" != "active" ]]; then
        U_65_2=1
        log_basis "[U_65_2] Chrony 설치됨 but 서비스 비활성" "취약"
    else
        # 설정 파일 확인
        if [[ -f "/etc/chrony/chrony.conf" ]]; then
            SERVER_CONF=$(run_cmd "[U_65_2] Chrony 서버 설정 확인" "grep -E '^server|^pool' /etc/chrony/chrony.conf | grep -v '^#' || echo 'none'")
            if [[ "$SERVER_CONF" == "none" ]]; then
                U_65_2=1
                log_basis "[U_65_2] Chrony 설정 파일 내 동기화 서버(server/pool) 설정 없음" "취약"
            else
                log_basis "[U_65_2] Chrony 동기화 서버 설정됨: $SERVER_CONF" "양호"
            fi
        else
            U_65_2=1
            TMP=$(run_cmd "[U_65_2] 설정 파일 확인" "ls /etc/chrony/chrony.conf 2>/dev/null || echo '미존재'")
            log_basis "[U_65_2] Chrony 설정 파일 미존재" "취약"
        fi
    fi
else
    # 미설치 시 0 (N/A)
    U_65_2=0
fi


# [U_65_3] NTP 설정 점검
if [[ "$HAS_NTP" -eq 1 ]]; then
    NTP_ACT=$(run_cmd "[U_65_3] NTP 서비스 상태" "systemctl is-active ntp 2>/dev/null || systemctl is-active ntpd 2>/dev/null || echo 'inactive'")
    
    if [[ "$NTP_ACT" != "active" ]]; then
        U_65_3=1
        log_basis "[U_65_3] NTP 설치됨 but 서비스 비활성" "취약"
    else
        if [[ -f "/etc/ntp.conf" ]]; then
            SERVER_CONF=$(run_cmd "[U_65_3] NTP 서버 설정 확인" "grep -E '^server|^pool' /etc/ntp.conf | grep -v '^#' || echo 'none'")
            if [[ "$SERVER_CONF" == "none" ]]; then
                U_65_3=1
                log_basis "[U_65_3] NTP 설정 파일 내 동기화 서버 설정 없음" "취약"
            else
                log_basis "[U_65_3] NTP 동기화 서버 설정됨: $SERVER_CONF" "양호"
            fi
        else
            U_65_3=1
            TMP=$(run_cmd "[U_65_3] 설정 파일 확인" "ls /etc/ntp.conf 2>/dev/null || echo '미존재'")
            log_basis "[U_65_3] NTP 설정 파일 미존재" "취약"
        fi
    fi
else
    U_65_3=0
fi

# 최종 취약 여부 판단
if [[ $U_65_1 -eq 1 || $U_65_2 -eq 1 || $U_65_3 -eq 1 ]]; then
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
    "category": "log",
    "flag": {
      "U_65_1": $U_65_1,
      "U_65_2": $U_65_2,
      "U_65_3": $U_65_3
    },
    "timestamp": "$DATE"
  }
}
EOF
