#!/bin/bash

# 자동 조치 가능 여부 : 수동 조치 권장
# 점검 내용 : sudoers 파일의 권한 및 설정 적절성 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_63_1 : sudoers 파일 권한 및 설정 취약 여부 (통합)
U_63_1=0

# --- 3. 점검 로직 수행 ---

SUDOERS_FILE="/etc/sudoers"

if [ -f "$SUDOERS_FILE" ]; then
    # [Step 1] 소유자 및 권한 확인 (root 권한 필요 시 sudo 사용, 에러는 버림)
    # 읽기 권한이 없으면 sudo 시도
    if [ -r "$SUDOERS_FILE" ]; then
        FILE_OWNER=$(stat -c "%U" "$SUDOERS_FILE")
        FILE_PERM=$(stat -c "%a" "$SUDOERS_FILE")
    else
        FILE_OWNER=$(sudo stat -c "%U" "$SUDOERS_FILE" 2>/dev/null)
        FILE_PERM=$(sudo stat -c "%a" "$SUDOERS_FILE" 2>/dev/null)
    fi

    # 판단 기준 1: 소유자가 root가 아니거나 권한이 640을 초과하는 경우
    if [ "$FILE_OWNER" != "root" ] || [ "$FILE_PERM" -gt 640 ]; then
        U_63_1=1
    fi

    # [Step 2] 내부 설정 확인 (NOPASSWD 및 과도한 권한)
    if [ -r "$SUDOERS_FILE" ]; then
        CONTENT=$(cat "$SUDOERS_FILE")
    else
        CONTENT=$(sudo cat "$SUDOERS_FILE" 2>/dev/null)
    fi

    if [ -n "$CONTENT" ]; then
        # 과도한 권한 (root, %sudo, %admin, Defaults 제외한 ALL=(ALL) ALL)
        EXCESSIVE_SUDO=$(echo "$CONTENT" | grep -vE "^#|^root|^%sudo|^%admin|^Defaults" | grep "ALL=(ALL" | grep "ALL")
        # NOPASSWD 설정 확인
        NOPASSWD_CHECK=$(echo "$CONTENT" | grep -v "^#" | grep "NOPASSWD")

        # 판단 기준 2: 취약한 설정이 발견되면 플래그 1 설정
        if [ -n "$EXCESSIVE_SUDO" ] || [ -n "$NOPASSWD_CHECK" ]; then
            U_63_1=1
        fi
    fi
else
    # 파일이 존재하지 않으면 양호(0) 또는 N/A
    U_63_1=0
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_63_1" -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- 5. JSON 출력 (Stdout) ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP_ADDR",
    "user": "$CURRENT_USER"
  },
  "result": {
    "flag_id": "U-63",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_63_1": $U_63_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
