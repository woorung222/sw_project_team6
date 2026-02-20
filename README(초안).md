# 프로젝트명: KISA ISMS-P 자동 진단 및 조치 프로젝트
---
---


## 프로젝트 소개
---
*프로젝트 개요 잘 버무려서 작성할 예정*
## 주요 기능
---
*프로젝트 상세에서 잘 버무려서 작성할 예정*
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
- 작업 방식:
- 운영 구조:
- 형상 관리:
- 가시성:
- 유지보수성:

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
