#!/bin/bash

# 자동 조치 가능 여부 : 수동 조치 권장 (apt upgrade 및 reboot)
# 점검 내용 : OS 버전 EOL 여부 및 커널 보안 패치 상태 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_64_1 : [System] 보안 관련 업데이트(Security) 미적용 상태
# U_64_2 : [Kernel] 최신 커널 설치 후 재부팅 미실행 (현재 커널 != 최신 커널)
U_64_1=0
U_64_2=0

# --- 3. 점검 로직 수행 ---

# [1. 보안 관련 업데이트 점검]
# apt-get -s dist-upgrade 명령을 통해 시뮬레이션 수행
# 'security' 키워드가 포함된 업데이트 패키지가 있는지 확인
SECURITY_UPDATES_CNT=$(apt-get -s dist-upgrade 2>/dev/null | grep -i "^Inst" | grep -i "security" | wc -l)

if [ "$SECURITY_UPDATES_CNT" -gt 0 ]; then
    U_64_1=1
fi

# [2. 커널 버전 불일치(재부팅 필요) 점검]
# 현재 구동 중인 커널 버전
CURRENT_KERNEL=$(uname -r)

# 설치된 커널 이미지 중 가장 높은 버전 확인 (메타 패키지 제외, 버전 순 정렬)
# dpkg -l 출력 예: ii  linux-image-6.8.0-31-generic ...
LATEST_INSTALLED_KERNEL=$(dpkg -l | grep "linux-image-[0-9]" | grep "^ii" | awk '{print $2}' | sort -V | tail -n 1)

# 최신 설치된 커널 패키지명에 현재 구동 중인 커널 버전 문자열이 포함되지 않으면 재부팅 필요 상태로 간주
# 예) Installed: linux-image-6.8.0-40-generic / Current: 6.8.0-31-generic -> 불일치(취약)
if [[ "$LATEST_INSTALLED_KERNEL" != *"$CURRENT_KERNEL"* ]]; then
    U_64_2=1
fi

# 추가 확인: Ubuntu의 reboot-required 플래그 파일 확인
if [ -f /var/run/reboot-required ]; then
    # 커널 관련 패키지로 인해 재부팅이 필요한 경우도 1로 설정
    if grep -q "linux-image" /var/run/reboot-required.pkgs 2>/dev/null; then
        U_64_2=1
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_64_1" -eq 1 ] || [ "$U_64_2" -eq 1 ]; then
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
    "flag_id": "U-64",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "patch",
    "flag": {
      "U_64_1": $U_64_1,
      "U_64_2": $U_64_2
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
