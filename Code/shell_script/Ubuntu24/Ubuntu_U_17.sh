#!/usr/bin/bash 
##### [U-17] 시스템 시작 스크립트 권한 설정
####### 점검내용: 시스템 시작 스크립트 권한 설정
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : 시스템 시작 스크립트 파일의 소유자가 root가 아니거나, 일반 사용자의 쓰기 권한이 부여된 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_17_1=0
U_17_2=0

# [init] 점검

INIT_DIR="/etc/rc.d"

if [ -d "$INIT_DIR" ]; then
    VULN_INIT=$(find -L "$INIT_DIR" -type f \( ! -user root -o -perm -o+w \) -print -quit 2>/dev/null)
    if [ -z "$VULN_INIT" ]; then
        U_17_1=0
		#echo "※ U-17 결과 : 양호(Good)" >> $resultfile 2>&1
    else
        U_17_1=1
		#echo "※ U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " /etc/rc.d 소유자가 root가 아니거나, 일반 사용자의 쓰기 권한이 부여되어 있습니다." >> $resultfile 2>&1
							
    fi
else
U_17_1=0
fi

# [systemd] 점검

SYSTEMD_DIR="/etc/systemd/system"
if [ -d "$SYSTEMD_DIR" ]; then
    VULN_SYSTEMD=$(find -L "$SYSTEMD_DIR" -type f \( ! -user root -o -perm -o+w \) -print -quit 2>/dev/null)
    if [ -z "$VULN_SYSTEMD" ]; then
        U_17_2=0
		#echo "※ U-17 결과 : 양호(Good)" >> $resultfile 2>&1
    else
        U_17_2=1
		#echo "※ U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " /etc/systemd/system 소유자가 root가 아니거나, 일반 사용자의 쓰기 권한이 부여되어 있습니다." >> $resultfile 2>&1
    fi
else
U_17_2=0
fi

if [ [$U_17_1 -eq 1] || [$U_17_2 -eq 1] ]; then
	IS_VUL=1
else 
	IS_VUL=0
fi

	 cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-17",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_17_1": $U_17_1,
	  "U_17_2": $U_17_2
    },
    "timestamp": "$DATE"
  }
}
EOF