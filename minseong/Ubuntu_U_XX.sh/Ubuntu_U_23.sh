#!/usr/bin/bash 
##### [U-23] SUID, SGID, Sticky bit 설정 파일 점검
####### 점검내용: 불필요하거나 악의적인 파일에 SUID, SGID, Sticky bit 설정 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : 주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여된 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_23_1=0


executables=("/sbin/dump" "/sbin/restore" "/sbin/unix_chkpwd" "/usr/bin/at" "/usr/bin/lpq" "/usr/bin/lpq-lpd" "/usr/bin/lpr" "/usr/bin/lpr-lpd" "/usr/bin/lprm" "/usr/bin/lprm-lpd" "/usr/bin/newgrp" "/usr/sbin/lpc" "/usr/sbin/lpc-lpd" "/usr/sbin/traceroute")
	for ((i=0; i<${#executables[@]}; i++))
	do
		if [ -f ${executables[$i]} ]; then
			if [ `ls -l ${executables[$i]} | awk '{print substr($1,2,9)}' | grep -i 's' | wc -l` -gt 0 ]; then
				#echo "※ U-23 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				#echo " 주요 실행 파일의 권한에 SUID나 SGID에 대한 설정이 부여되어 있습니다." >> $resultfile 2>&1
				 U_23_1=1

			fi
		fi
	done
  IS_VUL=$U_23_1
	#echo "※ U-23 결과 : 양호(Good)" >> $resultfile 2>&1
	 	cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-23",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_23_1": $U_23_1,
    },
    "timestamp": "$DATE"
  }
}
EOF