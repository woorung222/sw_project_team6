#!/bin/bash

# [U-40] NFS 접근 통제
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.89-92
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_40_1 : [파일 권한] /etc/exports 권한 644 초과 또는 소유자 오류
#   U_40_2 : [접근 설정] 전체 호스트(*) 접근 허용 설정 발견

# --- 점검 로직 시작 ---

# 초기화
U_40_1=0
U_40_2=0

EXPORTS_FILE="/etc/exports"

# 파일 존재 여부 확인 (파일이 없으면 NFS 미사용으로 간주하여 양호/0 유지)
if [[ -f "$EXPORTS_FILE" ]]; then

    # 1. [파일 권한] 점검 (U_40_1)
    # 기준: 소유자 root, 권한 644 이하
    OWNER=$(stat -c "%U" "$EXPORTS_FILE")
    PERM=$(stat -c "%a" "$EXPORTS_FILE")

    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 644 ]]; then
        U_40_1=1
    fi

    # 2. [접근 설정] 점검 (U_40_2)
    # 기준: 접속 허용 대상을 특정 IP나 호스트로 제한해야 함 (* 사용 금지)
    # 주석(#) 제외하고 내용 중 '*' 문자가 포함되어 있는지 확인
    if grep -v "^#" "$EXPORTS_FILE" 2>/dev/null | grep -F "*" >/dev/null 2>&1; then
        U_40_2=1
    fi

fi

# 3. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_40_1 -eq 1 ]] || [[ $U_40_2 -eq 1 ]]; then
    IS_VUL=1
fi

# 4. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
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
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
