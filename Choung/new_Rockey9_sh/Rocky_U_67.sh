#!/bin/bash

# [U-67] 로그 디렉터리 소유자 및 권한 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.171
# 자동 조치 가능 유무 : 가능 (소유자 및 권한 변경)
# 플래그 설명:
#   U_67_1 : [File] 주요 로그 파일의 소유자가 root가 아니거나 권한이 644보다 큼

# --- 점검 로직 시작 ---

# 초기화
U_67_1=0

# 점검할 주요 로그 파일 목록
# Rocky Linux 9 / RHEL 계열 주요 로그
LOG_FILES=(
    "/var/log/messages"
    "/var/log/secure"
    "/var/log/maillog"
    "/var/log/cron"
    "/var/log/boot.log"
    "/var/log/dmesg"
    "/var/log/syslog"
)

# 파일 순회 점검
for FILE in "${LOG_FILES[@]}"; do
    if [[ -f "$FILE" ]]; then
        # 소유자 및 권한 확인
        OWNER=$(stat -c "%U" "$FILE")
        PERM=$(stat -c "%a" "$FILE")
        
        # 통합 점검 로직
        # 1. 소유자가 root가 아님
        # 2. 권한이 644보다 큼 (예: 664, 666 등 - 그룹/타인 쓰기 권한)
        if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 644 ]]; then
            U_67_1=1
        fi
    fi
done

# 전체 취약 여부 판단
IS_VUL=$U_67_1

# JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-67",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "log",
    "flag": {
      "U_67_1": $U_67_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
