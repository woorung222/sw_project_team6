#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 주요 파일 전송 서비스(FTP, vsFTP, ProFTP, NFS, Samba)의 익명 접속 및 취약 설정 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_35_1=0  # 기본 FTP (in.ftpd 등) 익명 접속 및 서비스 상태
U_35_2=0  # vsFTPd 익명 접속 허용 여부
U_35_3=0  # ProFTPd 익명 접속 허용 여부
U_35_4=0  # NFS (Network File System) 공유 설정의 insecure/anonymous 여부
U_35_5=0  # Samba (SMB/CIFS) Guest 접속 허용 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-35] 점검 시작: 파일 공유 서비스 보안 설정 전수 점검"

# [U_35_1] 기본 FTP 서비스 점검
# inetd/xinetd 기반 또는 기본 ftpd 점검
if sudo grep -rE "ftp" /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null | grep -v "^#" > /dev/null; then
    echo "▶ 기본 FTP: [ 취약 ] inetd/xinetd에 FTP 서비스가 활성화되어 있습니다."
    U_35_1=1
    VULN_FLAGS="$VULN_FLAGS U_35_1"
else
    echo "▶ 기본 FTP: [ 양호 ]"
fi

# [U_35_2] vsFTPd 익명 접속 점검
if [ -f "/etc/vsftpd.conf" ]; then
    if sudo grep -i "anonymous_enable=YES" /etc/vsftpd.conf | grep -v "^#" > /dev/null; then
        echo "▶ vsFTPd: [ 취약 ] anonymous_enable 설정이 YES입니다."
        U_35_2=1
        VULN_FLAGS="$VULN_FLAGS U_35_2"
    else
        echo "▶ vsFTPd: [ 양호 ]"
    fi
else
    echo "▶ vsFTPd: [ 정보 ] 설정 파일이 존재하지 않습니다."
fi

# [U_35_3] ProFTPd 익명 접속 점검
if [ -f "/etc/proftpd/proftpd.conf" ]; then
    if sudo grep -i "<Anonymous" /etc/proftpd/proftpd.conf | grep -v "^#" > /dev/null; then
        echo "▶ ProFTPd: [ 취약 ] <Anonymous> 섹션이 활성화되어 있습니다."
        U_35_3=1
        VULN_FLAGS="$VULN_FLAGS U_35_3"
    else
        echo "▶ ProFTPd: [ 양호 ]"
    fi
else
    echo "▶ ProFTPd: [ 정보 ] 설정 파일이 존재하지 않습니다."
fi

# [U_35_4] NFS 공유 설정 점검
# /etc/exports 파일에서 보안상 취약한 옵션(insecure, all_squash 등) 확인
if [ -f "/etc/exports" ]; then
    if sudo grep -E "(insecure|all_squash|no_root_squash|anonuid|anongid)" /etc/exports | grep -v "^#" > /dev/null; then
        echo "▶ NFS: [ 취약 ] 익명 접근 권한 또는 보안에 취약한 공유 옵션이 발견되었습니다."
        U_35_4=1
        VULN_FLAGS="$VULN_FLAGS U_35_4"
    else
        echo "▶ NFS: [ 양호 ]"
    fi
else
    echo "▶ NFS: [ 정보 ] 설정 파일이 존재하지 않습니다."
fi

# [U_35_5] Samba Guest 접속 점검
if [ -f "/etc/samba/smb.conf" ]; then
    if sudo grep -Ei "(guest ok = yes|map to guest = bad user|public = yes)" /etc/samba/smb.conf | grep -v "^#" > /dev/null; then
        echo "▶ Samba: [ 취약 ] Guest 또는 Public 접속이 허용되어 있습니다."
        U_35_5=1
        VULN_FLAGS="$VULN_FLAGS U_35_5"
    else
        echo "▶ Samba: [ 양호 ]"
    fi
else
    echo "▶ Samba: [ 정보 ] 설정 파일이 존재하지 않습니다."
fi

echo "----------------------------------------------------"
echo "U_35_1 : $U_35_1"
echo "U_35_2 : $U_35_2"
echo "U_35_3 : $U_35_3"
echo "U_35_4 : $U_35_4"
echo "U_35_5 : $U_35_5"

# 최종 판정
if [[ $U_35_1 -eq 0 && $U_35_2 -eq 0 && $U_35_3 -eq 0 && $U_35_4 -eq 0 && $U_35_5 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
