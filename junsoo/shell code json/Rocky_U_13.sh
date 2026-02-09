#!/bin/bash

# [U-13] 안전한 비밀번호 암호화 알고리즘 사용 여부 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : SHA-2 (SHA-256, SHA-512) 이상의 안전한 암호화 알고리즘을 사용하는 경우 양호
#            (Rocky 9의 기본값인 Yescrypt도 안전한 알고리즘으로 간주)

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_13_1=0 # 0: 양호, 1: 취약
IS_VUL=0

# --- 점검 시작 ---

# Step 1) /etc/shadow 파일 내 root 계정 암호화 해시 확인
# 해시 식별자: $1$(MD5), $2$(Blowfish), $5$(SHA-256), $6$(SHA-512), $y$(Yescrypt-Rocky9 default)
SHADOW_HASH=$(grep "^root:" /etc/shadow | awk -F: '{print $2}')

# 패스워드가 설정되어 있지 않은 경우(!, *)는 제외하고, 설정된 경우 해시 앞부분 확인
IS_WEAK_HASH=0
if [[ "$SHADOW_HASH" != "!" ]] && [[ "$SHADOW_HASH" != "*" ]]; then
    if [[ "$SHADOW_HASH" == \$1\$* ]] || [[ "$SHADOW_HASH" == \$2\$* ]]; then
        IS_WEAK_HASH=1
    fi
    # SHA-256($5), SHA-512($6), Yescrypt($y)는 안전함
fi

# Step 2) /etc/login.defs 파일 내 ENCRYPT_METHOD 값 확인
LOGIN_DEFS_METHOD=$(grep "^ENCRYPT_METHOD" /etc/login.defs | grep -v "^#" | awk '{print $2}')
IS_WEAK_METHOD=0

# 설정값이 없거나, SHA512/SHA256/YESCRYPT가 아니면 취약으로 간주
# (Rocky 9에서는 보통 SHA512 또는 YESCRYPT 사용)
if [[ ! "$LOGIN_DEFS_METHOD" =~ ^(SHA512|SHA256|YESCRYPT)$ ]]; then
    # 값이 비어있을 경우, OS 기본값을 따르지만 명시적 설정을 권장하는 경우 취약 처리 가능
    # 여기서는 값이 명시적으로 MD5, DES 등이거나 비어있으면 취약으로 판단
    if [ -z "$LOGIN_DEFS_METHOD" ]; then
         # 최신 리눅스는 login.defs보다 PAM/authselect를 따르지만, 가이드 기준에 따라 설정 확인
         # 설정이 없으면 확인 필요(여기서는 일단 양호로 보거나, 엄격하게 취약 처리 가능)
         # 가이드: "ENCRYPT_METHOD SHA-2 이상 설정" -> 설정이 없으면 취약
         IS_WEAK_METHOD=1
    elif [[ "$LOGIN_DEFS_METHOD" == "MD5" ]] || [[ "$LOGIN_DEFS_METHOD" == "DES" ]]; then
         IS_WEAK_METHOD=1
    fi
fi

# Step 3) /etc/pam.d/system-auth 파일 내 안전한 알고리즘 설정 확인
# pam_unix.so 라인에 md5 등의 취약한 옵션이 있는지 확인
PAM_WEAK=0
if [ -f "/etc/pam.d/system-auth" ]; then
    if grep -E "pam_unix.so.*md5" /etc/pam.d/system-auth | grep -v "^#" > /dev/null; then
        PAM_WEAK=1
    fi
fi

# --- 종합 판단 ---
# 세 가지 항목 중 하나라도 취약하면 U_13_1 = 1
if [ $IS_WEAK_HASH -eq 1 ] || [ $IS_WEAK_METHOD -eq 1 ] || [ $PAM_WEAK -eq 1 ]; then
    U_13_1=1
    IS_VUL=1
else
    U_13_1=0
    IS_VUL=0
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