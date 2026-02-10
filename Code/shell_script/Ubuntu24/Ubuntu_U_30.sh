#!/usr/bin/bash 
##### [U-30]UMASK 설정 관리
####### 점검내용: 시스템 UMASK 값이 022 이상 설정 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu 24.04
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : UMASK 값이 022 미만으로 설정된 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_30_1=0
U_30_2=0


umaks_value=`umask`
	if [ ${umaks_value:2:1} -lt 2 ]; then
		#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
		 U_30_1=1
	elif [ ${umaks_value:3:1} -lt 2 ]; then
		#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
		 		 U_30_1=1
	else
	U_30_1=0
	fi
	# /etc/profile 파일 내 umask 설정 확인함
	etc_profile_umask_count=`grep -vE '^#|^\s#' /etc/profile | grep -i 'umask' | grep -vE 'if|\`' | grep '=' | wc -l` # 설정 파일에 <umask=값> 형식으로 umask 값이 설정된 경우
	etc_profile_umask_count2=`grep -vE '^#|^\s#' /etc/profile | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}' | wc -l` # 설정 파일에 <umask 값> 형식으로 umask 값이 설정된 경우
	if [ -f /etc/profile ]; then
		if [ $etc_profile_umask_count -gt 0 ]; then
			umaks_value=(`grep -vE '^#|^\s#' /etc/profile | grep -i 'umask' | grep -vE 'if|\`' | awk -F = '{gsub(" ", "", $0); print $2}'`)
			for ((i=0; i<${#umaks_value[@]}; i++))
			do
				if [ ${#umaks_value[$i]} -eq 2 ]; then
					if [ ${umaks_value[$i]:0:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1

					elif [ ${umaks_value[$i]:1:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					fi
				elif [ ${#umaks_value[$i]} -eq 4 ]; then
					if [ ${umaks_value[$i]:2:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					elif [ ${umaks_value[$i]:3:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					fi
				elif [ ${#umaks_value[$i]} -eq 3 ]; then
					if [ ${umaks_value[$i]:1:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					elif [ ${umaks_value[$i]:2:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					fi
				elif [ ${#umaks_value[$i]} -eq 1 ]; then
					#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " /etc/profile 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
					 U_30_1=1
				else
					#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " /etc/profile 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
					 U_30_1=1
				fi
			done
		elif [ $etc_profile_umask_count2 -gt 0 ]; then
			umaks_value=(`grep -vE '^#|^\s#' /etc/profile | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}'`)
			for ((i=0; i<${#umaks_value[@]}; i++))
			do
				if [ ${#umaks_value[$i]} -eq 2 ]; then
					if [ ${umaks_value[$i]:0:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					elif [ ${umaks_value[$i]:1:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					fi
				elif [ ${#umaks_value[$i]} -eq 4 ]; then
					if [ ${umaks_value[$i]:2:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					elif [ ${umaks_value[$i]:3:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					fi
				elif [ ${#umaks_value[$i]} -eq 3 ]; then
					if [ ${umaks_value[$i]:1:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						 U_30_1=1
					elif [ ${umaks_value[$i]:2:1} -lt 2 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						U_30_1=1 
					fi
				elif [ ${#umaks_value[$i]} -eq 1 ]; then
					#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " /etc/profile 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
					U_30_1=1 
				else
					#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " /etc/profile 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
					 U_30_1=1
				fi
			done
		fi
	fi
	# /etc/login.defs 파일 내 umask 설정 확인함
	umask_settings_files=("/etc/login.defs")
	for ((i=0; i<${#umask_settings_files[@]}; i++))
	do
		if [ -f ${umask_settings_files[$i]} ]; then
			file_umask_count=`grep -vE '^#|^\s#' ${umask_settings_files[$i]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}' | wc -l`
			if [ $file_umask_count -gt 0 ]; then
				umaks_value=(`grep -vE '^#|^\s#' ${umask_settings_files[$i]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}'`)
				for ((j=0; j<${#umaks_value[@]}; j++))
				do
					if [ ${#umaks_value[$j]} -eq 2 ]; then
						if [ ${umaks_value[$j]:0:1} -lt 2 ]; then
							#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " ${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							  U_30_2=1
						elif [ ${umaks_value[$j]:1:1} -lt 2 ]; then
							#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " ${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							 U_30_2=1
						fi
					elif [ ${#umaks_value[$j]} -eq 4 ]; then
						if [ ${umaks_value[$j]:2:1} -lt 2 ]; then
							#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " ${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							 U_30_2=1
						elif [ ${umaks_value[$j]:3:1} -lt 2 ]; then
							#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " ${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							 U_30_2=1
						fi
					elif [ ${#umaks_value[$j]} -eq 3 ]; then
						if [ ${umaks_value[$j]:1:1} -lt 2 ]; then
							#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " ${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							 U_30_2=1
						elif [ ${umaks_value[$j]:2:1} -lt 2 ]; then
							#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							#echo " ${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							 U_30_2=1
						fi
					elif [ ${#umaks_value[$j]} -eq 1 ]; then
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " ${umask_settings_files[$i]} 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						U_30_2=1 
					else
						#echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " ${umask_settings_files[$i]} 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
						U_30_2=1
					fi
				done
			fi
		fi
	done
	#"※ U-30 결과 : 양호(Good)" >> $resultfile 2>&1
	if [ $U_30_1 -eq 1 ] || [ $U_30_2 -eq 1 ]; then
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
    "flag_id": "U-30",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_30_1": $U_30_1,
	  "U_30_2": $U_30_2
    },
    "timestamp": "$DATE"
  }
}
EOF	 