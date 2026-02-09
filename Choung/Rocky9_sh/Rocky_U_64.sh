#!/bin/bash

# [U-64] 주기적 보안 패치 및 벤더 권고사항 적용
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.160-163 
# 점검 목적 : 최신 보안 패치를 적용하여 알려진 취약점(CVE)에 의한 침해 사고 예방
# 자동 조치 가능 유무 : 불가능 (서비스 영향도 검토 후 관리자가 직접 dnf update 수행 필요)
# 플래그 설명:
#   U_64_1 : [System] 보안 관련 업데이트(Security)가 존재함 (패치 미적용)
#   U_64_2 : [Kernel] 실행 중인 커널 버전이 설치된 최신 커널 버전과 다름 (업데이트 후 미재부팅)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-64] 주기적 보안 패치 및 벤더 권고사항 적용 점검 시작"
echo "----------------------------------------------------------------"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# 1. OS 및 커널 버전 정보 출력
OS_RELEASE=$(cat /etc/rocky-release 2>/dev/null)
KERNEL_VER=$(uname -r)
echo -e "${YELLOW}[정보]${NC} 시스템 버전 정보"
echo -e "   -> OS: $OS_RELEASE"
echo -e "   -> Kernel: $KERNEL_VER"

# 2. 보안 업데이트 대기 목록 확인 (dnf check-update --security)
# 리턴코드: 100(업데이트 있음), 0(없음), 1(오류)
echo -e "${YELLOW}[정보]${NC} 보안 업데이트 대기 목록을 확인합니다. (네트워크 연결 필요)"

# dnf 명령어가 있는지 확인
if command -v dnf &> /dev/null; then
    # --security 옵션으로 보안 패치만 조회
    # (시간이 조금 걸릴 수 있음)
    DNF_OUTPUT=$(dnf check-update --security 2>&1)
    DNF_EXIT_CODE=$?

    if [[ $DNF_EXIT_CODE -eq 100 ]]; then
        # 업데이트 있음
        SEC_COUNT=$(echo "$DNF_OUTPUT" | grep -v "^Last metadata" | grep -v "^$" | wc -l)
        
        VULN_STATUS=1
        VULN_FLAGS+=("U_64_1")
        echo -e "${RED}[취약]${NC} [System] 적용되지 않은 보안 업데이트가 존재합니다. (약 ${SEC_COUNT}개)"
        echo -e "   -> 확인 명령: dnf updateinfo list security"
        
    elif [[ $DNF_EXIT_CODE -eq 0 ]]; then
        # 업데이트 없음
        echo -e "${GREEN}[양호]${NC} [System] 모든 보안 업데이트가 적용되어 있습니다."
    else
        # 오류 (네트워크 단절 등)
        echo -e "${YELLOW}[경고]${NC} [System] 보안 업데이트 확인 실패 (네트워크 연결 또는 리포지토리 설정 확인 필요)"
        echo -e "   -> Error: $DNF_OUTPUT"
    fi
else
    echo -e "${YELLOW}[정보]${NC} dnf 명령어를 찾을 수 없습니다."
fi

# 3. 커널 버전 일치 여부 확인 (재부팅 누락 점검)
# 설치된 커널 패키지 중 가장 최신 버전 확인
LATEST_INSTALLED_KERNEL=$(rpm -q kernel --qf "%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort -V | tail -n 1)

if [[ -n "$LATEST_INSTALLED_KERNEL" ]]; then
    if [[ "$KERNEL_VER" != "$LATEST_INSTALLED_KERNEL" ]]; then
        # 실행 중인 커널이 설치된 최신 커널과 다름 (업데이트 후 재부팅 안 함)
        VULN_STATUS=1
        VULN_FLAGS+=("U_64_2")
        echo -e "${RED}[취약]${NC} [Kernel] 최신 커널이 설치되었으나 적용되지 않았습니다. (재부팅 필요)"
        echo -e "   -> 현재: $KERNEL_VER"
        echo -e "   -> 최신: $LATEST_INSTALLED_KERNEL"
    else
        echo -e "${GREEN}[양호]${NC} [Kernel] 현재 최신 버전의 커널로 부팅되어 있습니다."
    fi
fi

# 4. 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (최신 보안 패치 적용 상태)"
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 5. 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
