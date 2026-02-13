#!/usr/bin/bash 
##### [U-29]hosts.lpd 파일 소유자 및 권한 설정
####### 점검내용: /etc/hosts.lpd 파일의 제거 및 권한 적절성 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu 24.04
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : /etc/hosts.lpd 파일이 존재하며, 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_29_1=0


if [ -f /etc/hosts.lpd ]; then
		etc_hostslpd_owner_name=`ls -l /etc/hosts.lpd | awk '{print $3}'`
		if [[ $etc_hostslpd_owner_name =~ root ]]; then
			etc_hostslpd_permission=`stat /etc/hosts.lpd | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_hostslpd_permission -le 600 ]; then
				#echo "※ U-29 결과 : 양호(Good)" >> $resultfile 2>&1
				 U_29_1=0
			else
				#echo "※ U-29 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				#echo " /etc/hosts.lpd 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
				 U_29_1=1

			fi
		else
			#echo "※ U-29 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			#echo " /etc/hosts.lpd 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			 U_29_1=1

		fi
	else
		#echo "※ U-29 결과 : 양호(Good)" >> $resultfile 2>&1
		 U_29_1=0
	fi
	IS_VUL=$U_29_1
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-29",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_29_1": $U_29_1,
    },
    "timestamp": "$DATE"
  }
}
EOF	 