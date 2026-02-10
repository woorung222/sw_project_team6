#!/usr/bin/bash 
##### [U-28]접속 IP 및 포트 제한
####### 점검내용: 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : 접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정하지 않은 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_28_1=0
U_28_2=0
U_28_3=0
U_28_4=0



#echo " ### /etc/hosts.deny 파일에 ALL:ALL 설정이 없거나 /etc/hosts.allow 파일에 ALL:ALL 설정이 있을 경우 취약으로 판단" >> $resultfile 2>&1
	#echo " ### iptables 사용 시 수동 점검을 추가로 진행하세요." >> $resultfile 2>&1
	if [ -f /etc/hosts.deny ]; then
		etc_hostsdeny_allall_count=`grep -vE '^#|^\s#' /etc/hosts.deny | awk '{gsub(" ", "", $0); print}' | grep -i 'all:all' | wc -l`
		if [ $etc_hostsdeny_allall_count -gt 0 ]; then
			if [ -f /etc/hosts.allow ]; then
				etc_hostsallow_allall_count=`grep -vE '^#|^\s#' /etc/hosts.allow | awk '{gsub(" ", "", $0); print}' | grep -i 'all:all' | wc -l`
				if [ $etc_hostsallow_allall_count -gt 0 ]; then
					#echo "※ U-28_1 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " /etc/hosts.allow 파일에 'ALL : ALL' 설정이 있습니다." >> $resultfile 2>&1
					 U_28_1=1

				else
					#echo "※ U-28_1 결과 : 양호(Good)" >> $resultfile 2>&1
					 U_28_1=0
				fi
			else
				#echo "※ U-28_1 결과 : 양호(Good)" >> $resultfile 2>&1
				 U_28_1=0
			fi
		else
			#echo "※ U-28_1 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			#echo " /etc/hosts.deny 파일에 'ALL : ALL' 설정이 없습니다." >> $resultfile 2>&1
			 U_28_1=1
		fi
	else
		#echo "※ U-28_1 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " /etc/hosts.deny 파일이 없습니다." >> $resultfile 2>&1
		 U_28_1=1
	fi

IPTABLES_CNT=$(iptables -nL INPUT 2>/dev/null | grep -v "^Chain" | grep -v "^target" | wc -l)
if [ "$IPTABLES_CNT" -gt 0 ]; then
    #echo "※ U-28_2 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
	#echo " IPTABLE이 활성화 되어있습니다." >> $resultfile 2>&1
	U_28_2=1
else
U_28_2=0
fi


if systemctl is-active --quiet firewalld; then
    ZONE=$(firewall-cmd --get-active-zones 2>/dev/null)
    #echo "※ U-28_3 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
	#echo " FIREWALL이 활성화 되어있습니다" >> $resultfile 2>&1
	U_28_3=1
else
U_28_3=0
fi


if -v ufw &> /dev/null; then
    UFW_STATUS=$(ufw status | grep "Status: active")
    if [ ! -z "$UFW_STATUS" ]; then
	#echo "※ U-28_4 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
	#echo " UFW가 활성화 되어있습니다." >> $resultfile 2>&1
	U_28_4=1
    fi
else
U_28_4=0
fi


if [ $U_28_1 -eq 1 ] || [ $U_28_2 -eq 1 ] || [ $U_28_3 -eq 1 ] || [ $U_28_4 -eq 1 ]; then
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
    "flag_id": "U-28",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_28_1": $U_28_1,
	  "U_28_2": $U_28_2,
	  "U_28_3": $U_28_3,
	  "U_28_4": $U_28_4
    },
    "timestamp": "$DATE"
  }
}
EOF