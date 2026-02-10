
#!/usr/bin/bash 
##### [U-20] /etc/(x)inetd.conf 파일 소유자 및 권한 설정
####### 점검내용: /etc/(x)inetd.conf 파일 권한 적절성 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건]: /etc/(x)inetd.conf 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우]

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_20_1=0 #inetd
U_20_2=0 #xinetd
U_20_3=0 #systemd


file_exists_count=0
	if [ -f /etc/inetd.conf ]; then
		((file_exists_count++))
		etc_inetdconf_owner_name=`ls -l /etc/inetd.conf | awk '{print $3}'`
		if [[ $etc_inetdconf_owner_name =~ root ]]; then
			etc_inetdconf_permission=`stat /etc/inetd.conf | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_inetdconf_permission -ne 600 ]; then
				#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				#echo " /etc/inetd.conf 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
				U_20_1=1

			fi
		else
			#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			#echo " /etc/inetd.conf 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			U_20_1=1
		fi
	fi

if [ -f /etc/xinetd.conf ]; then
		((file_exists_count++))
		etc_xinetdconf_owner_name=`ls -l /etc/xinetd.conf | awk '{print $3}'`
		if [[ $etc_xinetdconf_owner_name =~ root ]]; then
			etc_xinetdconf_permission=`stat /etc/xinetd.conf | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_xinetdconf_permission -ne 600 ]; then
				#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				#echo " /etc/xinetd.conf 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
				 U_20_2=1
			fi
		else
			#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			#echo " /etc/xinetd.conf 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			U_20_2=1
		fi
else
#echo "※ U-20 결과 : 양호(Good)" >> $resultfile 2>&1
							U_20_1=0
fi
if [ -d /etc/xinetd.d ]; then
		etc_xinetdd_file_count=`find /etc/xinetd.d -type f 2>/dev/null | wc -l`
		if [ $etc_xinetdd_file_count -gt 0 ]; then
			xinetdd_files=(`find /etc/xinetd.d -type f 2>/dev/null`)
			for ((i=0; i<${#xinetdd_files[@]}; i++))
			do
				xinetdd_file_owner_name=`ls -l ${xinetdd_files[$i]} | awk '{print $3}'`
				if [[ $xinetdd_file_owner_name =~ root ]]; then
					xinetdd_file_permission=`stat ${xinetdd_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
					if [ $xinetdd_file_permission -ne 600 ]; then
						#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/xinetd.d 디렉터리 내 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
						U_20_2=1

					fi
				else
					#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " /etc/xinetd.d 디렉터리 내 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
					 	U_20_2=1

				fi
			done
		fi
else
	#echo "※ U-20 결과 : 양호(Good)" >> $resultfile 2>&1
							U_20_2=0
fi

if [ -f /etc/system.conf ]; then
		((file_exists_count++))
		etc_systemconf_owner_name=`ls -l /etc/system.conf | awk '{print $3}'`
		if [[ $etc_systemconf_owner_name =~ root ]]; then
			etc_systemconf_permission=`stat /etc/system.conf | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_systemconf_permission -ne 600 ]; then
				#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				#echo " /etc/system.conf 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
				 U_20_3=1
			fi
		else
			#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			#echo " /etc/system.conf 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			U_20_3=1

		fi
else
		#echo "※ U-20 결과 : 양호(Good)" >> $resultfile 2>&1
							U_20_3=0
fi
    #systemd 하위 모든 폴더 점검
if [ -d /etc/systemd ]; then
		etc_systemd_file_count=`find /etc/systemd/* -type f 2>/dev/null | wc -l`
		if [ $etc_systemd_file_count -gt 0 ]; then
			systemd_files=(`find /etc/systemd -type f 2>/dev/null`)
			for ((i=0; i<${#systemd_files[@]}; i++))
			do
				systemd_file_owner_name=`ls -l ${systemd_files[$i]} | awk '{print $3}'`
				if [[ $systemd_file_owner_name =~ root ]]; then
					systemd_file_permission=`stat ${systemd_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
					if [ $systemd_file_permission -ne 600 ]; then
						#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " $systemd_files[$i] 디렉터리 내 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
						U_20_3=1

					fi
				else
					#echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " /etc/systemd 디렉터리 내 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
					U_20_3=1
				fi
			done
		fi
else
#echo "※ U-19 결과 : 양호(Good)" >> $resultfile 2>&1
							U_20_3=0
fi

if [ $U_20_1 -eq 1 ] || [ $U_20_2 -eq 1 ] || [ $U_20_3 -eq 1 ]; then
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
    "flag_id": "U-20",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_20_1": $U_20_1,
	  "U_20_2": $U_20_2,
	  "U_20_3": $U_20_3
    },
    "timestamp": "$DATE"
  }
}
EOF