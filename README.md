# 프로젝트명: KISA ISMS-P 자동 진단 및 조치 프로젝트
---
---


## 프로젝트 소개
---
- 최근 대형 보안 사고 대량 발생 -> 보안 취약점 관심 증가
- ISMS-P 인증: 기업 내 정보보호 및 개인정보보호 수준 인증 중 하나(2019~2025년 간 인증 통계 증가)
- 매 회 수동 진단 및 반복 작업 시 업무 효율성 저하 및 생산성 감소
- 자동 진단 및 배포 도구 제작을 통한 업무 효율성 증가(w.Ansible)
- 웹 대시보드를 통한 데이터 접근성 강화
- 진단 취약점 체크리스트를 통한 사후 검증 용이

## 주요 기능
---
- 자동화 엔진 구현( 자동 진단 및 자동 조치 )
- Flag를 이용한 분기처리
- 다중 서비스 환경 자동 식별 및 분기 처리
- OS 자동 식별 기반 조치 분기 처리
- 상태 기반 자동 조치
- Watchdog 기반 DB 자동 적재
- 수동 조치 필요 항목에 대한 대응 프로세스

## 기술 스택
---
- Web: Streamlit, Figma
- DB: PostgreSQL 16.11
- Automation: Ansible
- Backend: Python, Bash
- Infrastructure: Ubuntu 22.04.3 LTS, Rocky Linux 9.7
- Communication: Notion, Github, Discord

## 시스템 아키텍처
---

#### <Loadmap>
<img src="img/Screenshot 2026-02-20 110242.png" >

#### <DB Architecture>
<img src="img/ ">
<img src="img/ ">

#### <Ansible Playbook Module Architecture>

├── isms-ansible                      # 최상위 root 

│   ├── ansible.cfg

│   ├── common                        # 로그 설정 

│   │   └── common_logging.sh

│   ├── inventory                     # target server 설정 

│   │   ├── group_vars

│   │   ├── host_vars

│   │   └── prod                      # - target server - ip 선언

│   ├── playbooks                     # 실질적인 진입점 

│   │   ├── check.yml                 # - 진단 

│   │   └── remediate.yml             # - 조치 

│   ├── results                       # 결과 저장 

│   │   ├── remediate                 # - 조치 

│   │   └── scan                      # - 진단

│   ├── roles                         # 진단/조치 실제 tasks 영역 

│   │   ├── account                 

│   │   │   ├── defaults              # - 기본적으로 선언된 플래그(ex. U_01~U_13)

│   │   │   │   └── main.yml          

│   │   │   ├── scripts               

│   │   │   │   ├── rocky

│   │   │   │   └── ubuntu

│   │   │   └── tasks                 # - 작성 스크립트

│   │   │       ├── check.yml         # -- 스크립트를 돌리는 yaml 

│   │   │       ├── main.yml

│   │   │       ├── remediate.yml

│   │   │       └── remediations      # --- yaml 파일들 

│   │   ├── file

│   │   │   ├── defaults

│   │   │   │   └── main.yml

│   │   │   ├── scripts

│   │   │   │   ├── rocky

│   │   │   │   └── ubuntu

│   │   │   └── tasks

│   │   │       ├── check.yml

│   │   │       ├── main.yml

│   │   │       ├── remediate.yml

│   │   │       └── remediations

│   │   ├── log

│   │   │   ├── defaults

│   │   │   │   └── main.yml

│   │   │   ├── scripts

│   │   │   │   ├── rocky

│   │   │   │   └── ubuntu

│   │   │   └── tasks

│   │   │       ├── check.yml

│   │   │       ├── main.yml

│   │   │       ├── remediate.yml

│   │   │       └── remediations

│   │   ├── patch

│   │   │   ├── defaults

│   │   │   │   └── main.yml

│   │   │   ├── scripts

│   │   │   │   ├── rocky

│   │   │   │   └── ubuntu

│   │   │   └── tasks

│   │   │       ├── check.yml

│   │   │       ├── main.yml

│   │   │       ├── remediate.yml

│   │   │       └── remediations

│   │   └── service

│   │       ├── defaults

│   │       │   └── main.yml

│   │       ├── scripts

│   │       │   ├── rocky

│   │       │   └── ubuntu

│   │       └── tasks

│   │           ├── check.yml

│   │           ├── main.yml

│   │           ├── remediate.yml

│   │           └── remediations


## As-Is -> To-Be

---

| \ | As-Is | > | To-Be |
| --- | --- | --- | --- |
| 작업 방식 | 순차적 자동 점검 |  | 병렬식 자동 일괄 점검 |
| 운영 구조 | 개별 서버 단위의 분산 관리 |  | Control Node 기반 중앙 집중 관리 -> 효율성 향상|
| 형상 관리 | 스크립트 기반 일회성 조치 |  | 코드 기반(IaC) 표준 형상 관리 |
| 가시성 | 서버별 개별 텍스트(CLI) 기반 확인 |  | Dashboard 기반 진단/조치 현황 가시화 |
|  |  |  | - 전체 보안 이행률 (Pie chart) <br>- 상세 진단 및 클릭 조치(List, Action Button) |
| 유지보수성 | OS별 파편화된 관리 |  | 추상화 모듈 기반 통합 관리 |


## 예상 성과 ( <- 자체 평가에 해당)
---
[기술적 성과]
-  환경 구성 완성 측면
- 시스템 구성 완성 측면
- 구현 완성 측면

[운영적 성과]
- 일정 달성 평가
- 협업 및 역할 수행 체계
- 문제 해결 및 개선 대응 역량

## 한계점
---
- 대시보드 초기 설계 미흡
- 기존 Json, Log 구조 설계 미흡
- 보안 정책상 보안 담당자 수작업 항목 존재
- 공통 로직 모듈화 미반영

## 개선 방향
---
- App/Helper 등의 기능 모듈화
- 변수 및 저장 형식 등 명확한 사전 정의 필요
- 사용자 인터랙션 기반 조건 판단
- 중복 코드 모듈화 
