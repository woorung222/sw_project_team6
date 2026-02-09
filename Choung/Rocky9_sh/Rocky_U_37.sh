#!/bin/bash

# [U-37] crontab 설정파일 권한 설정 미흡
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.80-81
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_37_1 : [crontab 명령어] SUID 설정되어 있거나 일반 사용자 실행 허용
#   U_37_2 : [at 명령어] SUID 설정되어 있거나 일반 사용자 실행 허용
#   U_37_3 : [cron 설정 파일] 권한 640 초과 또는 소유자가 root가 아님
#   U_37_4 : [at 설정 파일] 권한 640 초과 또는 소유자가 root가 아님

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-37] crontab 설정파일 권한 설정 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 1. [crontab 명령어] 점검 (U_37_1) - PDF p.81
CRON_BIN="/usr/bin/crontab"
if [[ -f "$CRON_BIN" ]]; then
    # SUID 확인 (4000 bit) 또는 Other Execute (x) 확인
    # 가이드 p.81: "crontab 명령어는 SUID가 설정되어 있으므로 SUID 설정 제거 필요" 
    # 가이드 p.80: "일반 사용자 실행 권한이 제거되어 있으며" [cite: 312]
    BIN_PERM=$(stat -c "%a" "$CRON_BIN")
    
    # SUID(4xxx)가 있거나, Others 권한에 실행(1)이 있는 경우 취약
    if [[ "$BIN_PERM" -ge 4000 ]] || [[ $((BIN_PERM % 10 % 2)) -eq 1 ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_37_1")
        echo -e "${RED}[취약]${NC} [crontab 명령어] $CRON_BIN 권한($BIN_PERM)이 취약합니다. (SUID 존재 또는 일반사용자 실행 허용)"
    fi
fi

# 2. [at 명령어] 점검 (U_37_2) - PDF p.81
AT_BIN="/usr/bin/at"
if [[ -f "$AT_BIN" ]]; then
    # SUID 확인 및 Other Execute 확인 
    BIN_PERM=$(stat -c "%a" "$AT_BIN")
    
    if [[ "$BIN_PERM" -ge 4000 ]] || [[ $((BIN_PERM % 10 % 2)) -eq 1 ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_37_2")
        echo -e "${RED}[취약]${NC} [at 명령어] $AT_BIN 권한($BIN_PERM)이 취약합니다. (SUID 존재 또는 일반사용자 실행 허용)"
    fi
fi

# 3. [cron 설정 파일] 점검 (U_37_3) - PDF p.81
# 점검 대상 파일 및 디렉터리 목록 [cite: 335-338]
CHECK_LIST=("/etc/crontab" "/etc/cron.allow" "/etc/cron.deny" "/var/spool/cron")
# 디렉터리 내 파일 전수 조사를 위한 배열 추가
CRON_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly")

# 단일 파일 점검
for file in "${CHECK_LIST[@]}"; do
    if [[ -f "$file" ]]; then
        OWNER=$(stat -c "%U" "$file")
        PERM=$(stat -c "%a" "$file")
        
        # 소유자 root 아님 OR 권한 640 초과 (644, 666, 777 등) [cite: 314]
        # 640 = rw-r-----
        # 644 = rw-r--r-- (Vulnerable according to guide)
        if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
            VULN_STATUS=1
            [[ ! " ${VULN_FLAGS[@]} " =~ " U_37_3 " ]] && VULN_FLAGS+=("U_37_3")
            echo -e "${RED}[취약]${NC} [cron 설정 파일] $file (소유자:$OWNER, 권한:$PERM) - 640 이하/root 권고"
        fi
    elif [[ -d "$file" ]]; then
        # 디렉터리인 경우 (/var/spool/cron 등) 내부 파일 점검 필요
        BAD_FILES=$(find "$file" -type f \( ! -user root -o -perm /027 \))
        if [[ -n "$BAD_FILES" ]]; then
             VULN_STATUS=1
             [[ ! " ${VULN_FLAGS[@]} " =~ " U_37_3 " ]] && VULN_FLAGS+=("U_37_3")
             echo -e "${RED}[취약]${NC} [cron 설정 파일] $file 디렉터리 내 취약한 파일이 발견되었습니다."
        fi
    fi
done

# cron 디렉터리 내부 파일 점검
for dir in "${CRON_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        # root가 아니거나, 권한이 640(rw-r-----)보다 '개방된' 부분이 있는 파일 찾기
        # -perm /027 : Group에 w(2) 있거나, Other에 rwx(7) 중 하나라도 있으면 탐지
        FOUND=$(find "$dir" -type f \( ! -user root -o -perm /027 \) -print -quit)
        if [[ -n "$FOUND" ]]; then
             VULN_STATUS=1
             [[ ! " ${VULN_FLAGS[@]} " =~ " U_37_3 " ]] && VULN_FLAGS+=("U_37_3")
             echo -e "${RED}[취약]${NC} [cron 설정 파일] $dir 내부에 권한 640 초과 또는 비 root 소유 파일이 있습니다."
        fi
    fi
done

# 4. [at 설정 파일] 점검 (U_37_4) - PDF p.81
AT_FILES=("/etc/at.allow" "/etc/at.deny")
for file in "${AT_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        OWNER=$(stat -c "%U" "$file")
        PERM=$(stat -c "%a" "$file")
        
        if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
             VULN_STATUS=1
             VULN_FLAGS+=("U_37_4")
             echo -e "${RED}[취약]${NC} [at 설정 파일] $file (소유자:$OWNER, 권한:$PERM) - 640 이하/root 권고"
        fi
    fi
done

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} crontab/at 명령어 및 설정 파일 권한이 안전합니다."
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
