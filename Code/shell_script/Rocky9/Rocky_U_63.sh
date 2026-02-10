#!/bin/bash

# [U-63] sudo 명령어 접근 관리
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.159
# 점검 목적 : 관리자 권한을 부여하는 설정 파일(sudoers)의 비인가 수정을 방지하기 위함
# 자동 조치 가능 유무 : 가능 (파일 소유자 및 권한 변경)
# 플래그 설명:
#   U_63_1 : [File] /etc/sudoers 소유자(root) 또는 권한(640 이하) 미흡

# --- 점검 로직 시작 ---

# 초기화
U_63_1=0

# 1. 패키지 설치 여부 확인
# sudo 패키지가 설치되어 있어야 점검 진행
if rpm -qa | grep -qE "^sudo-[0-9]"; then
    
    SUDOERS_FILE="/etc/sudoers"
    
    # 2. 파일 점검 (U_63_1)
    if [[ -f "$SUDOERS_FILE" ]]; then
        # 파일 정보 추출
        OWNER=$(stat -c "%U" "$SUDOERS_FILE")
        PERM=$(stat -c "%a" "$SUDOERS_FILE")
        
        # 통합 점검 로직
        # 조건 1: 소유자가 root가 아님
        # 조건 2: 권한이 640보다 큼 (644, 666, 777 등)
        if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
            U_63_1=1
        fi
    else
        # 패키지는 있으나 설정 파일이 없는 경우 (특이 케이스)
        # 보안상 위험은 없으므로 0 유지 (혹은 관리적 미흡으로 볼 수도 있으나 로직상 Pass)
        :
    fi
fi

# 3. 전체 취약 여부 판단
IS_VUL=$U_63_1

# 4. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-63",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service_management",
    "flag": {
      "U_63_1": $U_63_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
