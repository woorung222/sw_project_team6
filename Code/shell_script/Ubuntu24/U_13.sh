#!/usr/bin/env bash
set -u

# =========================================================
# U_13 (상) 안전한 패스워드 알고리즘 설정 | Ubuntu 24.04
# - 진단 기준: 패스워드 암호화 알고리즘이 SHA-512(또는 yescrypt) 이상인지 점검
# - Rocky 논리 반영:
#   1) /etc/login.defs의 ENCRYPT_METHOD 확인
#   2) /etc/pam.d/common-password의 sha512/yescrypt 옵션 확인
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_13"
CATEGORY="account"
IS_AUTO=1  # 알고리즘 설정 자동화 가능

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_13_1=0

# -------------------------
# 1) [U_13_1] 암호화 알고리즘 점검
# -------------------------
LOGIN_DEFS="/etc/login.defs"
PAM_PW="/etc/pam.d/common-password"
WEAK_FOUND=0

# 1-1. login.defs 확인 (ENCRYPT_METHOD)
# Ubuntu 최신 버전은 login.defs보다 PAM 설정을 우선하지만, 명시적으로 취약한 설정(MD5, DES)이 있으면 취약
if [ -f "$LOGIN_DEFS" ]; then
    METHOD=$(grep "^ENCRYPT_METHOD" "$LOGIN_DEFS" | grep -v "^#" | awk '{print $2}')
    if [ -n "$METHOD" ]; then
        # SHA512, SHA256, YESCRYPT가 아니면 취약으로 간주
        if [[ ! "$METHOD" =~ ^(SHA512|SHA256|YESCRYPT)$ ]]; then
            WEAK_FOUND=1
        fi
    fi
fi

# 1-2. PAM 설정 확인 (common-password)
# Ubuntu는 기본적으로 pam_unix.so 대신 pam_pwquality.so 등을 사용하거나 
# pam_unix.so 라인에 sha512 또는 yescrypt 옵션이 있어야 함
if [ -f "$PAM_PW" ]; then
    # 주석 제외하고 pam_unix.so 라인 찾기
    if grep -v "^#" "$PAM_PW" | grep -q "pam_unix.so"; then
        # sha512, sha256, yescrypt 옵션이 없는지 확인
        if ! grep -v "^#" "$PAM_PW" | grep "pam_unix.so" | grep -qE "(sha512|sha256|yescrypt)"; then
             # 옵션이 없으면 기본적으로 md5로 동작할 수 있어 확인 필요 (Ubuntu 기본은 sha512이나 명시적 확인)
             # 단, Ubuntu 24.04는 기본이 yescrypt이나 pam 파일에 명시 안되어 있을 수 있음.
             # 여기서는 "md5"나 "blowfish" 등 취약한 알고리즘이 명시되었는지를 기준으로 보거나,
             # 안전한 알고리즘이 '없으면' 취약으로 볼 수 있음.
             # Rocky 로직에 맞춰 "안전한 알고리즘이 명시되지 않으면" 취약으로 판단
             WEAK_FOUND=1
        fi
    fi
fi

if [ "$WEAK_FOUND" -eq 1 ]; then
    FLAG_U_13_1=1
else
    FLAG_U_13_1=0
fi

# -------------------------
# 2) VULN_STATUS
# -------------------------
IS_VUL=$FLAG_U_13_1

# -------------------------
# 3) Output (JSON)
# -------------------------
cat <<EOF
{
  "meta": {
    "hostname": "$HOST",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": {
      "U_13_1": $FLAG_U_13_1
    },
    "timestamp": "$DATE"
  }
}
EOF