#!/bin/bash

# [U-13] 안전한 비밀번호 암호화 알고리즘 사용 여부 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : SHA-2 (SHA-256, SHA-512) 이상의 안전한 암호화 알고리즘을 사용하는 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-13"
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

# 초기 상태 설정
U_13_1=0 # 0: 양호, 1: 취약
IS_VUL=0

# --- 점검 시작 ---

# Step 1) /etc/shadow 파일 내 root 계정 암호화 해시 확인
SHADOW_HASH=$(run_cmd "[U_13_1] root 계정 패스워드 해시 확인" "grep '^root:' /etc/shadow | awk -F: '{print \$2}'")

IS_WEAK_HASH=0
if [[ "$SHADOW_HASH" != "!" ]] && [[ "$SHADOW_HASH" != "*" ]]; then
    if [[ "$SHADOW_HASH" == \$1\$* ]] || [[ "$SHADOW_HASH" == \$2\$* ]]; then
        IS_WEAK_HASH=1
    fi
fi

# Step 2) /etc/login.defs 파일 내 ENCRYPT_METHOD 값 확인
LOGIN_DEFS_METHOD=$(run_cmd "[U_13_1] login.defs 암호화 방식 확인" "grep '^ENCRYPT_METHOD' /etc/login.defs | grep -v '^#' | awk '{print \$2}'")
IS_WEAK_METHOD=0

if [[ ! "$LOGIN_DEFS_METHOD" =~ ^(SHA512|SHA256|YESCRYPT)$ ]]; then
    if [ -z "$LOGIN_DEFS_METHOD" ]; then
         IS_WEAK_METHOD=1
    elif [[ "$LOGIN_DEFS_METHOD" == "MD5" ]] || [[ "$LOGIN_DEFS_METHOD" == "DES" ]]; then
         IS_WEAK_METHOD=1
    fi
fi

# Step 3) /etc/pam.d/system-auth 파일 내 안전한 알고리즘 설정 확인
PAM_WEAK=0
if [ -f "/etc/pam.d/system-auth" ]; then
    CMD_PAM="grep -E 'pam_unix.so.*md5' /etc/pam.d/system-auth | grep -v '^#'"
    PAM_CHECK=$(run_cmd "[U_13_1] PAM 설정 내 취약 알고리즘 확인" "$CMD_PAM")
    if [ -n "$PAM_CHECK" ]; then
        PAM_WEAK=1
    fi
fi

# --- 종합 판단 ---
if [ $IS_WEAK_HASH -eq 1 ] || [ $IS_WEAK_METHOD -eq 1 ] || [ $PAM_WEAK -eq 1 ]; then
    U_13_1=1
    IS_VUL=1
    log_basis "[U_13_1] 취약한 암호화 알고리즘이 발견됨 (Shadow: $IS_WEAK_HASH, Login.defs: $IS_WEAK_METHOD, PAM: $PAM_WEAK)" "취약"
else
    U_13_1=0
    IS_VUL=0
    log_basis "[U_13_1] 안전한 패스워드 암호화 알고리즘 사용 중" "양호"
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-13",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_13_1": $U_13_1
    },
    "timestamp": "$DATE"
  }
}
EOF
