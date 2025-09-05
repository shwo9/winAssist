# Windows AI Assistant (Powered by ChatGPT) 🤖

현대적인 Python 기반 Windows 데스크톱 애플리케이션으로, ChatGPT와의 실시간 채팅을 제공합니다.
OAuth 인증과 OpenAI API 키를 모두 지원하며, 기업 환경에서도 안정적으로 작동합니다.

## ✨ 주요 기능

### 🔐 **듀얼 인증 시스템**
- **OAuth 로그인**: ChatGPT 웹 계정으로 직접 로그인
- **API 키 지원**: OpenAI API 키로 대체 인증
- **토큰 자동 관리**: 로그인 정보 자동 저장/복원

### 🎨 **모던 UI/UX**
- **다크 테마**: 시각적으로 편안한 인터페이스
- **실시간 채팅**: 스트리밍 응답 표시
- **반응형 디자인**: 깔끔하고 직관적인 레이아웃

### 🛡️ **기업 환경 지원**
- **SSL 우회**: 회사 네트워크 환경 대응
- **안정성**: 403/400 에러 자동 복구
- **토큰 갱신**: 만료된 인증 자동 갱신

### ⚡ **고급 기능**
- **Codex API 통합**: OpenAI의 공식 백엔드 API 사용
- **세션 영속화**: 재시작 시 자동 로그인
- **에러 처리**: 상세한 오류 로깅 및 복구

## 🚀 설치 및 실행

### 요구사항
```bash
Python 3.8+
```

### 설치
```bash
# 저장소 클론
git clone <repository-url>
cd winai

# 의존성 설치
pip install -r requirements.txt
```

### 실행
```bash
python main.py
```

## 📖 사용법

### 1. 인증 설정
- **OAuth 방식**: "🚀 ChatGPT 로그인" 버튼 클릭
- **API 키 방식**: OpenAI API 키 입력

### 2. 채팅 시작
- 메시지 입력창에 질문 입력
- Enter 키 또는 전송 버튼 클릭
- 실시간으로 ChatGPT 응답 표시

### 3. 세션 관리
- 인증 정보 자동 저장
- 재시작 시 자동 복원
- 토큰 만료 시 자동 갱신

## 🏗️ 프로젝트 구조

```
winai/
│
├── main.py                    # 메인 애플리케이션
├── requirements.txt           # Python 의존성
├── README.md                  # 프로젝트 설명
├── CHANGELOG.md               # 변경 기록
├── codex/                     # Codex 참조 자료
│   └── codex-rs/
│       └── core/
│           └── prompt.md      # Codex instructions
└── .winai/                    # 사용자 데이터 (자동 생성)
    └── auth.json              # 인증 토큰 저장
```

## 🛠️ 기술 스택

- **UI Framework**: CustomTkinter
- **HTTP Client**: requests
- **Authentication**: OAuth 2.0 (PKCE)
- **Backend API**: ChatGPT Codex API
- **Async Processing**: Threading
- **Data Storage**: JSON 파일

## 🔧 설정

### SSL 우회 (기업 환경)
회사 네트워크에서 SSL 인증서 문제가 발생할 경우:
```python
# main.py에서 자동으로 처리됨
verify=False  # SSL 검증 우회
```

### 토큰 저장 위치
```
~/.winai/auth.json  # Windows: C:\Users\[사용자]\.winai\auth.json
```

## 📝 개발자 노트

이 프로젝트는 OpenAI의 Codex CLI를 참고하여 개발되었으며,
ChatGPT의 공식 백엔드 API를 사용하여 안정적인 통신을 보장합니다.

## 📄 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다.
