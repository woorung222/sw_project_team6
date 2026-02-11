#!/bin/bash

# [U-02] 비밀번호 관리정책 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-02"
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
U_02_1=1; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. PAM 적용 여부 점검
PAM_FILE="/etc/pam.d/common-password"
PAM_PWQUALITY=$(run_cmd "[U_02_1] pam_pwquality.so 모듈 적용 확인" "grep -v '^\s*#' $PAM_FILE 2>/dev/null | grep -E '\bpam_pwquality\.so\b|\bpam_pwquality\b' || echo 'not_set'")

# 2. pwquality 설정 점검
CONF="/etc/security/pwquality.conf"
MINLEN=$(run_cmd "[U_02_1] 비밀번호 최소 길이(minlen) 확인" "grep -E '^\s*minlen\s*=' $CONF 2>/dev/null | tail -n 1 | awk -F= '{print \$2}' | tr -d ' ' || echo 'not_set'")
CREDITS=$(run_cmd "[U_02_1] 복잡도 설정(credit/minclass) 확인" "grep -Eq '^\s*(dcredit|ucredit|lcredit|ocredit|minclass)\s*=' $CONF 2>/dev/null && echo 'set' || echo 'not_set'")

# 판정
OK_MINLEN=0
if [[ "$MINLEN" =~ ^[0-9]+$ ]] && [ "$MINLEN" -ge 8 ]; then OK_MINLEN=1; fi

if [[ "$PAM_PWQUALITY" != "not_set" ]] && [ "$OK_MINLEN" -eq 1 ] && [[ "$CREDITS" == "set" ]]; then
    U_02_1=0
    log_basis "[U_02_1] 비밀번호 정책 설정이 양호함 (PAM 적용, 길이 8이상, 복잡도 설정 포함)" "양호"
else
    U_02_1=1
    log_basis "[U_02_1] 비밀번호 정책 설정이 미흡함 (PAM: $PAM_PWQUALITY, 길이: $MINLEN, 복잡도: $CREDITS)" "취약"
fi

IS_VUL=$U_02_1

# --- JSON 출력 (구조 유지) ---
cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_02_1": $U_02_1
    },
    "timestamp": "$DATE"
  }
}
EOF
