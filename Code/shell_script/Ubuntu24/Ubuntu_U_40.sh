#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : NFS 서비스 이용 시 /etc/exports 파일의 권한 및 접근 제어 설정 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_40_1 : /etc/exports 파일 소유자 및 권한 설정 점검
# U_40_2 : /etc/exports 파일 내 접근 허용 대상 및 권한 설정 점검
U_40_1=0
U_40_2=0

# --- 3. 점검 로직 수행 ---

# [Step 1] /etc/exports 파일 소유자 및 권한 확인
if [ -f "/etc/exports" ]; then
    OWNER=$(stat -c "%U" /etc/exports)
    PERM=$(stat -c "%a" /etc/exports)
    
    # 양호 기준: 소유자 root, 권한 644 이하
    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 644 ]]; then
        U_40_1=1
    fi
else
    # 파일이 없으면 양호로 간주 (NFS를 안 쓴다는 의미일 수 있음)
    U_40_1=0
fi

# [Step 2] /etc/exports 파일 내 접근 설정 확인
if [ -f "/etc/exports" ]; then
    # 주석(#)과 빈 줄을 제외한 실제 설정 내용 읽기
    EXPORT_CONTENT=$(sudo cat /etc/exports | grep -v "^#" | grep -v "^$")

    if [ -n "$EXPORT_CONTENT" ]; then
        # 취약 기준: 
        # 1. 접속 대상에 와일드카드 '*' 사용 (모두 허용)
        # 2. 'no_root_squash' 옵션 사용 (루트 권한 허용)
        # 3. 'insecure' 옵션 사용 (비특권 포트 허용)
        VULN_CHECK=$(echo "$EXPORT_CONTENT" | grep -E "\*|no_root_squash|insecure")
        
        if [ -n "$VULN_CHECK" ]; then
            U_40_2=1
        fi
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_40_1" -eq 1 ] || [ "$U_40_2" -eq 1 ]; then
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
    "flag_id": "U-40",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_40_1": $U_40_1,
      "U_40_2": $U_40_2
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
