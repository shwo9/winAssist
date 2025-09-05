# main.py
import customtkinter as ctk
import threading
import asyncio
import requests
import json
import uuid
import datetime
import time
import os
import base64
import hashlib
import secrets
import webbrowser
import warnings
from flask import Flask, request, redirect
from urllib.parse import urlencode, urlparse, parse_qs
from playwright.async_api import async_playwright
from playwright_stealth import Stealth

# SSL 경고 억제 (회사 환경 대응)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
requests.packages.urllib3.disable_warnings()

# 모던 디자인 설정
ctk.set_appearance_mode("dark")  # dark | light | system
ctk.set_default_color_theme("dark-blue")  # blue-accent modern look

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 모던 윈도우 설정
        self.title("✨ Windows AI Assistant")
        self.geometry("900x700")
        self.resizable(True, True)
        self.configure(fg_color="#1a1a1a")  # 다크 배경

        # --- Session & Chat State ---
        self.captured_headers = {}
        self.session_captured = threading.Event()
        self.chat_lock = threading.Lock()
        self.conversation_id = None
        self.parent_message_id = None
        self.auth_data = {}  # OAuth 인증 데이터 저장

        # --- Authentication Configuration ---
        self.use_api_key = False  # False = OAuth, True = API Key
        self.api_key = None

        # --- OAuth Configuration ---
        self.oauth_config = {
            'issuer': 'https://auth.openai.com',
            'client_id': 'app_EMoamEEZ73f0CkXaXp7hrann',  # Codex의 실제 client_id
            'redirect_uri': 'http://localhost:1455/auth/callback',
            'scope': 'openid profile email offline_access'
        }

        # --- Auth persistence ---
        self.auth_store_path = os.path.join(os.path.expanduser("~"), ".winai", "auth.json")
        self.chatgpt_account_id = None
        # 사용자 instructions 파일은 사용하지 않음 (Codex BASE만 사용)
        self.instructions_store_path = None

        # --- Flask OAuth Server ---
        self.oauth_server = None
        self.oauth_thread = None
        self._codex_base_instructions_cache = None

        # --- Layout Configuration ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- 모던 탑바 디자인 ---
        self.top_frame = ctk.CTkFrame(self, corner_radius=15, fg_color="#2b2b2b", border_width=1, border_color="#404040")
        self.top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self.top_frame.grid_columnconfigure(1, weight=1)

        # 타이틀 섹션
        self.title_label = ctk.CTkLabel(
            self.top_frame,
            text="🤖 Windows AI Assistant",
            font=("Segoe UI Semibold", 18, "bold"),
            text_color="#ffffff"
        )
        self.title_label.grid(row=0, column=0, padx=(20, 15), pady=(15, 8), sticky="w")

        # 인증 방식 선택 (모던 라디오 버튼)
        self.auth_frame = ctk.CTkFrame(self.top_frame, fg_color="transparent")
        self.auth_frame.grid(row=1, column=0, padx=(20, 15), pady=(0, 15), sticky="w")

        self.auth_var = ctk.StringVar(value="oauth")
        self.oauth_radio = ctk.CTkRadioButton(
            self.auth_frame,
            text="🔐 OAuth 로그인",
            variable=self.auth_var,
            value="oauth",
            font=("Segoe UI", 12),
            fg_color="#007acc",
            hover_color="#005999"
        )
        self.oauth_radio.grid(row=0, column=0, padx=(0, 20), pady=2)

        self.api_radio = ctk.CTkRadioButton(
            self.auth_frame,
            text="🔑 API 키",
            variable=self.auth_var,
            value="api",
            font=("Segoe UI", 12),
            fg_color="#007acc",
            hover_color="#005999"
        )
        self.api_radio.grid(row=0, column=1, padx=(0, 20), pady=2)

        # 중앙 버튼 섹션
        self.center_frame = ctk.CTkFrame(self.top_frame, fg_color="transparent")
        self.center_frame.grid(row=0, column=1, rowspan=2, padx=10, pady=10)

        self.login_button = ctk.CTkButton(
            self.center_frame,
            text="🚀 ChatGPT 로그인",
            command=self.start_authentication,
            font=("Segoe UI Semibold", 13),
            fg_color="#007acc",
            hover_color="#005999",
            corner_radius=8,
            height=35
        )
        self.login_button.grid(row=0, column=0, padx=5, pady=2)

        # API 키 입력 필드 (모던 디자인)
        self.api_key_entry = ctk.CTkEntry(
            self.center_frame,
            placeholder_text="🔐 OpenAI API 키를 입력하세요...",
            show="*",
            font=("Segoe UI", 12),
            corner_radius=8,
            height=35,
            fg_color="#333333",
            border_color="#555555"
        )
        self.api_key_entry.grid(row=1, column=0, padx=5, pady=2, sticky="ew")
        self.api_key_entry.grid_remove()  # 처음에는 숨김

        # 우측 상태 및 버튼 섹션
        self.right_frame = ctk.CTkFrame(self.top_frame, fg_color="transparent")
        self.right_frame.grid(row=0, column=2, rowspan=2, padx=(10, 20), pady=10)

        self.status_label = ctk.CTkLabel(
            self.right_frame,
            text="📊 상태: 시작 전",
            font=("Segoe UI", 12),
            text_color="#cccccc"
        )
        self.status_label.grid(row=0, column=0, padx=5, pady=2, sticky="w")

        self.save_button = ctk.CTkButton(
            self.right_frame,
            text="💾 저장",
            command=self.save_conversation,
            font=("Segoe UI", 11),
            fg_color="#28a745",
            hover_color="#218838",
            corner_radius=6,
            height=30,
            width=60
        )
        self.save_button.grid(row=1, column=0, padx=5, pady=2)

        # 인증 방식 변경 이벤트 연결
        self.auth_var.trace_add("write", self.on_auth_method_changed)

        # --- 모던 채팅 영역 ---
        self.chat_frame = ctk.CTkFrame(
            self,
            corner_radius=15,
            fg_color="#2b2b2b",
            border_width=1,
            border_color="#404040"
        )
        self.chat_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.chat_frame.grid_columnconfigure(0, weight=1)
        self.chat_frame.grid_rowconfigure(0, weight=1)

        self.textbox = ctk.CTkTextbox(
            self.chat_frame,
            wrap="word",
            font=("Consolas", 11),
            fg_color="#1e1e1e",
            border_width=0,
            corner_radius=10
        )
        self.textbox.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        self.textbox.insert("0.0", "💬 안녕하세요! '🚀 ChatGPT 로그인' 버튼을 눌러 세션을 연결해주세요.\n\n")
        self.textbox.configure(state="disabled")

        # --- 모던 입력 영역 ---
        self.bottom_frame = ctk.CTkFrame(
            self,
            corner_radius=15,
            fg_color="#2b2b2b",
            border_width=1,
            border_color="#404040"
        )
        self.bottom_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.bottom_frame.grid_columnconfigure(0, weight=1)

        self.entry = ctk.CTkEntry(
            self.bottom_frame,
            placeholder_text="💭 메시지를 입력하세요...",
            font=("Segoe UI", 12),
            corner_radius=25,
            height=45,
            fg_color="#333333",
            border_color="#555555",
            text_color="#ffffff"
        )
        self.entry.grid(row=0, column=0, padx=(20, 10), pady=15, sticky="ew")
        self.entry.bind("<Return>", self.send_message_thread)

        self.send_button = ctk.CTkButton(
            self.bottom_frame,
            text="📤 전송",
            command=self.send_message_thread,
            font=("Segoe UI Semibold", 12),
            fg_color="#007acc",
            hover_color="#005999",
            corner_radius=25,
            height=45,
            width=80
        )
        self.send_button.grid(row=0, column=1, padx=(0, 20), pady=15)

        # 로딩 인디케이터 (초기에는 숨김)
        self.loading_label = ctk.CTkLabel(
            self.bottom_frame,
            text="",
            font=("Segoe UI", 11),
            text_color="#9ca3af"
        )
        self.loading_label.grid(row=0, column=2, padx=(0, 10), pady=15, sticky="e")
        self._loading_anim_id = None

        # --- Load existing auth if present ---
        try:
            self.try_load_tokens()
        except Exception as init_load_error:
            print(f"[Auth] 초기 토큰 로드 실패: {init_load_error}")

    # --- Auth persistence/helpers ---
    def ensure_auth_dir(self):
        auth_dir = os.path.dirname(self.auth_store_path)
        if not os.path.isdir(auth_dir):
            os.makedirs(auth_dir, exist_ok=True)

    def persist_tokens(self):
        self.ensure_auth_dir()
        payload = {
            'tokens': self.auth_data,
            'last_saved': int(time.time())
        }
        with open(self.auth_store_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"[Auth] 토큰 저장됨: {self.auth_store_path}")

    def try_load_tokens(self):
        if not os.path.isfile(self.auth_store_path):
            return
        with open(self.auth_store_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        tokens = data.get('tokens') or {}
        if 'access_token' in tokens:
            self.auth_data = tokens
            try:
                self.extract_account_id_from_id_token(tokens.get('id_token'))
            except Exception as e:
                print(f"[Auth] 저장된 id_token 파싱 실패: {e}")
            # 재구성된 헤더
            self.captured_headers = {
                'authorization': f"Bearer {tokens['access_token']}",
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
                'accept': 'text/event-stream',
                'accept-encoding': 'gzip, deflate, br, zstd',
                'accept-language': 'ko,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7,zh;q=0.6',
                'origin': 'https://chatgpt.com',
                'referer': 'https://chatgpt.com/'
            }
            if self.chatgpt_account_id:
                self.captured_headers['chatgpt-account-id'] = self.chatgpt_account_id
            self.session_captured.set()
            self.update_status_post_capture()
            print("[Auth] 저장된 토큰 불러옴")

    def extract_account_id_from_id_token(self, id_token: str | None):
        if not id_token:
            return
        try:
            parts = id_token.split('.')
            if len(parts) < 2:
                return
            payload_b64 = parts[1]
            # URL-safe base64 padding fix
            padding = '=' * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64 + padding).decode('utf-8')
            claims = json.loads(payload_json)
            auth_claims = claims.get('https://api.openai.com/auth') or {}
            self.chatgpt_account_id = auth_claims.get('chatgpt_account_id')
            if self.chatgpt_account_id:
                print(f"[Auth] chatgpt_account_id: {self.chatgpt_account_id}")
        except Exception as e:
            print(f"[Auth] id_token 파싱 오류: {e}")

    def refresh_access_token_if_needed(self) -> bool:
        try:
            if not self.auth_data or 'refresh_token' not in self.auth_data:
                return False
            # 토큰 유효성 대략 체크 (만료 임박 시 새로고침)
            # 실제 만료 시간은 서버에서 검증되므로, 403 발생 시 재시도에도 사용
            token_url = f"{self.oauth_config['issuer']}/oauth/token"
            data = {
                'grant_type': 'refresh_token',
                'client_id': self.oauth_config['client_id'],
                'refresh_token': self.auth_data['refresh_token']
            }
            resp = requests.post(token_url, data=data, verify=False)
            if resp.status_code == 200:
                tokens = resp.json()
                self.auth_data.update(tokens)
                try:
                    self.extract_account_id_from_id_token(tokens.get('id_token'))
                except Exception:
                    pass
                self.persist_tokens()
                # 헤더 갱신
                self.captured_headers['authorization'] = f"Bearer {self.auth_data['access_token']}"
                if self.chatgpt_account_id:
                    self.captured_headers['chatgpt-account-id'] = self.chatgpt_account_id
                print("[Auth] 액세스 토큰 갱신 완료")
                return True
            else:
                print(f"[Auth] 토큰 갱신 실패: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            print(f"[Auth] 토큰 갱신 중 오류: {e}")
            return False

    # --- Chat Logic ---
    def send_message_thread(self, event=None):
        user_input = self.entry.get().strip()
        if not user_input:
            return
        
        self.textbox_append(f"👤 나: {user_input}\n\n")
        self.entry.delete(0, "end")
        self.send_button.configure(state="disabled")

        thread = threading.Thread(target=self.send_message_request, args=(user_input,))
        thread.daemon = True
        thread.start()

    def send_message_request(self, text):
        if not self.session_captured.is_set():
            self.textbox_append("[오류] ChatGPT 세션이 연결되지 않았습니다.\n")
            self.after(0, lambda: self.send_button.configure(state="normal"))
            return

        with self.chat_lock:
            # 채팅창 내 로딩 플레이스홀더 표시
            self.after(0, self.start_stream_loading)
            if self.use_api_key:
                # OpenAI API 키 방식
                headers = {
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json'
                }
                url = "https://api.openai.com/v1/chat/completions"
                data = {
                    "model": "gpt-5",
                    "messages": [{"role": "user", "content": text}],
                    "stream": True
                }
                self.send_openai_api_request(url, headers, data)
            else:
                # OAuth 방식 (Codex Responses API 경로)
                self.send_chatgpt_codex_responses(text)

    # --- Authentication Methods ---
    def on_auth_method_changed(self, *args):
        """인증 방식 변경 이벤트 핸들러"""
        if self.auth_var.get() == "api":
            self.api_key_entry.grid()
            self.login_button.configure(text="🔑 API 키 설정")
        else:
            self.api_key_entry.grid_remove()
            self.login_button.configure(text="🚀 ChatGPT 로그인")

    def start_authentication(self):
        """선택된 인증 방식에 따라 로그인 시작"""
        if self.auth_var.get() == "api":
            self.setup_api_key_auth()
        else:
            self.start_oauth_login()

    def setup_api_key_auth(self):
        """API 키 인증 설정"""
        api_key = self.api_key_entry.get().strip()
        if not api_key:
            self.status_label.configure(text="상태: API 키를 입력해주세요", text_color="orange")
            return

        if not api_key.startswith("sk-"):
            self.status_label.configure(text="상태: 유효하지 않은 API 키 형식", text_color="red")
            return

        self.api_key = api_key
        self.use_api_key = True
        self.session_captured.set()
        self.status_label.configure(text="상태: API 키 인증 완료", text_color="green")
        self.textbox_append("\n[시스템] API 키 인증이 완료되었습니다. 이제 앱에서 대화할 수 있습니다.\n")
        self.login_button.configure(state="disabled")

    # --- Session Capture Logic ---
    def start_oauth_login(self):
        """OAuth 기반 ChatGPT 로그인 시작"""
        self.login_button.configure(state="disabled")
        self.status_label.configure(text="상태: OAuth 서버 시작 중...")
        thread = threading.Thread(target=self.run_oauth_login)
        thread.daemon = True
        thread.start()

    def run_oauth_login(self):
        """OAuth 로그인 프로세스 실행"""
        try:
            # OAuth 서버 시작
            self.start_oauth_server()

            # PKCE 챌린지 생성 및 저장
            self.code_verifier, code_challenge = self.generate_pkce()

            # 상태 값 생성 및 저장
            self.oauth_state = self.generate_state()

            # 인증 URL 생성
            auth_url = self.build_authorize_url(code_challenge, self.oauth_state)

            # 브라우저에서 인증 URL 열기
            self.status_label.configure(text="상태: 브라우저에서 로그인 완료해주세요...")
            webbrowser.open(auth_url)

            print(f"[OAuth] 인증 URL: {auth_url}")
            print(f"[OAuth] 코드 검증자 저장됨: {self.code_verifier[:20]}...")
            print("[OAuth] 브라우저에서 ChatGPT 로그인을 완료해주세요.")

        except Exception as e:
            print(f"[OAuth] 로그인 시작 실패: {e}")
            self.status_label.configure(text="상태: 로그인 시작 실패")
            self.login_button.configure(state="normal")

    # --- OAuth Methods ---
    def start_oauth_server(self):
        """Flask OAuth 서버 시작"""
        if self.oauth_server is None:
            self.oauth_server = Flask(__name__)

            @self.oauth_server.route('/auth/callback')
            def oauth_callback():
                code = request.args.get('code')
                state = request.args.get('state')
                error = request.args.get('error')

                print(f"[OAuth] 콜백 수신 - 코드: {code[:20] if code else 'None'}, 상태: {state}, 오류: {error}")

                if error:
                    print(f"[OAuth] 인증 오류: {error}")
                    return f"인증 오류: {error}"

                if not code:
                    return "인증 코드가 없습니다."

                # 상태 검증
                if hasattr(self, 'oauth_state') and state != self.oauth_state:
                    print(f"[OAuth] 상태 불일치 - 예상: {self.oauth_state}, 실제: {state}")
                    return "상태 검증 실패"

                # 인증 코드로 토큰 교환
                self.exchange_code_for_tokens(code)
                return "로그인 성공! 이 창을 닫아주세요."

            @self.oauth_server.route('/success')
            def success():
                return "인증이 완료되었습니다. 이 창을 닫아주세요."

        # 서버가 이미 실행 중이 아니면 시작
        if self.oauth_thread is None or not self.oauth_thread.is_alive():
            self.oauth_thread = threading.Thread(target=self.oauth_server.run,
                                               kwargs={'host': '127.0.0.1', 'port': 1455, 'debug': False})
            self.oauth_thread.daemon = True
            self.oauth_thread.start()
            print("[OAuth] Flask 서버 시작됨 (localhost:1455)")

    def generate_pkce(self):
        """PKCE 챌린지 생성"""
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        return code_verifier, code_challenge

    def generate_state(self):
        """OAuth 상태 값 생성"""
        return secrets.token_urlsafe(32)

    def build_authorize_url(self, code_challenge, state):
        """OAuth 인증 URL 생성"""
        params = {
            'response_type': 'code',
            'client_id': self.oauth_config['client_id'],
            'redirect_uri': self.oauth_config['redirect_uri'],
            'scope': self.oauth_config['scope'],
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'id_token_add_organizations': 'true',
            'codex_cli_simplified_flow': 'true',
            'state': state,
            'originator': 'codex-cli'
        }
        query_string = urlencode(params)
        return f"{self.oauth_config['issuer']}/oauth/authorize?{query_string}"

    def exchange_code_for_tokens(self, code):
        """인증 코드를 토큰으로 교환"""
        try:
            token_url = f"{self.oauth_config['issuer']}/oauth/token"

            # 저장된 PKCE 코드 검증자 사용
            if not hasattr(self, 'code_verifier'):
                print("[OAuth] 코드 검증자가 저장되지 않았습니다.")
                self.after(0, lambda: self.status_label.configure(text="상태: 코드 검증자 누락"))
                return

            code_verifier = self.code_verifier
            print(f"[OAuth] 토큰 교환 시도 - 코드: {code[:20]}..., 검증자: {code_verifier[:20]}...")

            data = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': self.oauth_config['redirect_uri'],
                'client_id': self.oauth_config['client_id'],
                'code_verifier': code_verifier
            }

            print(f"[OAuth] 토큰 요청 데이터: {data}")

            # SSL 검증 우회 (회사 환경 대응)
            response = requests.post(token_url, data=data, verify=False)
            print(f"[OAuth] 토큰 응답 상태: {response.status_code}")
            print(f"[OAuth] 토큰 응답 헤더: {dict(response.headers)}")

            if response.status_code == 200:
                tokens = response.json()
                print(f"[OAuth] 토큰 응답: {tokens}")

                if 'access_token' in tokens:
                    # 인증 성공
                    self.auth_data = tokens
                    # 파생 데이터 계산 및 저장
                    try:
                        self.extract_account_id_from_id_token(tokens.get('id_token'))
                    except Exception as parse_err:
                        print(f"[OAuth] id_token 파싱 실패: {parse_err}")
                    try:
                        self.persist_tokens()
                    except Exception as persist_err:
                        print(f"[OAuth] 토큰 저장 실패: {persist_err}")
                    self.session_captured.set()
                    self.after(0, lambda: self.update_status_post_capture())
                    print("[OAuth] 토큰 교환 성공!")
                    print(f"[OAuth] 액세스 토큰: {tokens['access_token'][:50]}...")

                    # 헤더 구성 (실제 Chrome 헤더와 유사하게)
                    self.captured_headers = {
                        'authorization': f"Bearer {tokens['access_token']}",
                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
                        'accept': 'text/event-stream',
                        'accept-encoding': 'gzip, deflate, br, zstd',
                        'accept-language': 'ko,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7,zh;q=0.6',
                        'origin': 'https://chatgpt.com',
                        'referer': 'https://chatgpt.com/'
                    }
                    if self.chatgpt_account_id:
                        self.captured_headers['chatgpt-account-id'] = self.chatgpt_account_id
                else:
                    print(f"[OAuth] 토큰 교환 실패 - 토큰 없음: {tokens}")
                    self.after(0, lambda: self.status_label.configure(text="상태: 토큰 교환 실패"))
            else:
                print(f"[OAuth] 토큰 교환 실패 - HTTP {response.status_code}")
                print(f"[OAuth] 응답 내용: {response.text}")
                err_text = response.text
                self.after(0, lambda t=err_text: self.status_label.configure(text=f"상태: 토큰 교환 실패: {t[:80]}"))

        except Exception as e:
            print(f"[OAuth] 토큰 교환 중 오류: {e}")
            self.after(0, lambda msg=str(e): self.status_label.configure(text=f"상태: 토큰 교환 실패: {msg}"))

    def send_openai_api_request(self, url, headers, data):
        """OpenAI API 요청 처리"""
        try:
            response = requests.post(url, headers=headers, json=data, stream=True, timeout=120, verify=False)
            response.raise_for_status()

            full_response = ""
            self.after(0, lambda: self.textbox_append("🤖 ChatGPT: "))

            for line in response.iter_lines():
                if line:
                    line_str = line.decode('utf-8').strip()
                    if line_str.startswith('data: '):
                        content = line_str[6:]
                        if content.strip() == '[DONE]':
                            break
                        try:
                            payload = json.loads(content)
                            if 'choices' in payload and payload['choices']:
                                choice = payload['choices'][0]
                                if 'delta' in choice and 'content' in choice['delta']:
                                    chunk = choice['delta']['content']
                                    if chunk:
                                        self.after(0, self.textbox_stream_update, chunk)
                                        full_response += chunk
                        except json.JSONDecodeError:
                            continue

            self.after(0, lambda: (self.finalize_stream_loading(),))

        except requests.RequestException as e:
            print(f"OpenAI API 요청 중 오류 발생: {e}")
            self.after(0, lambda: self.textbox_append(f"[오류] OpenAI API와 통신 중 문제가 발생했습니다: {e}\n"))
        finally:
            self.after(0, lambda: self.send_button.configure(state="normal"))

    def send_chatgpt_codex_responses(self, text: str):
        try:
            headers = self.captured_headers.copy()
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'text/event-stream'
            # Codex CLI가 추가하는 계정 헤더를 보강
            if self.chatgpt_account_id and 'chatgpt-account-id' not in headers:
                headers['chatgpt-account-id'] = self.chatgpt_account_id
            headers['OpenAI-Beta'] = 'responses=experimental'
            headers['originator'] = 'codex-cli'
            headers['version'] = '1.0.0'
            session_id = str(uuid.uuid4())
            headers['session_id'] = session_id

            # Codex 요청 페이로드 (필드 복원)
            data = {
                "model": "gpt-5",
                "instructions": self.load_codex_base_instructions(),
                "input": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": text}
                        ]
                    }
                ],
                "tools": [],
                "tool_choice": "auto",
                "parallel_tool_calls": False,
                "store": False,
                "stream": True,
                "include": [],
                "prompt_cache_key": session_id,
                "text": {"verbosity": "medium"}
            }

            url = "https://chatgpt.com/backend-api/codex/responses"
            response = requests.post(url, headers=headers, json=data, stream=True, timeout=120, verify=False)
            if response.status_code == 403:
                if self.refresh_access_token_if_needed():
                    headers['authorization'] = f"Bearer {self.auth_data['access_token']}"
                    response = requests.post(url, headers=headers, json=data, stream=True, timeout=120, verify=False)
            if not (200 <= response.status_code < 300):
                try:
                    err_body = response.text
                except Exception:
                    err_body = "<no-body>"
                msg = f"HTTP {response.status_code} {err_body[:500]}"  # 본문 일부만 표시
                print(f"[Codex] 요청 실패: {msg}")
                self.after(0, lambda m=msg: self.textbox_append(f"[오류] ChatGPT(Codex)와 통신 오류: {m}\n"))
                self.after(0, lambda: (self.send_button.configure(state="normal"), self.finalize_stream_loading()))
                return

            self.after(0, lambda: self.textbox_append("🤖 ChatGPT: "))
            for raw in response.iter_lines():
                if not raw:
                    continue
                line = raw.decode('utf-8').strip()
                if not line.startswith('data: '):
                    continue
                payload_str = line[6:]
                if payload_str.strip() == '[DONE]':
                    break
                try:
                    obj = json.loads(payload_str)
                except json.JSONDecodeError:
                    continue

                ev_type = obj.get('type') or obj.get('event')
                # Common patterns seen in Responses API streaming
                if ev_type in ("response.output_text.delta", "output_text.delta") and 'delta' in obj:
                    chunk = obj.get('delta') or ''
                    if chunk:
                        self.after(0, self.textbox_stream_update, chunk)
                elif ev_type in ("response.refusal.delta",) and 'delta' in obj:
                    chunk = obj.get('delta') or ''
                    if chunk:
                        self.after(0, self.textbox_stream_update, chunk)
                elif ev_type in ("message.delta", "content.delta") and 'delta' in obj:
                    delta = obj.get('delta')
                    if isinstance(delta, dict) and 'text' in delta:
                        chunk = delta['text']
                        self.after(0, self.textbox_stream_update, chunk)
                elif ev_type in ("response.completed", "response.error"):
                    break

            self.after(0, lambda: self.finalize_stream_loading())

        except requests.RequestException as e:
            msg = str(e)
            print(f"ChatGPT(Codex) 요청 중 오류 발생: {msg}")
            self.after(0, lambda m=msg: (self.textbox_append(f"[오류] ChatGPT(Codex)와 통신 중 문제가 발생했습니다: {m}\n"), self.finalize_stream_loading()))
        finally:
            self.after(0, lambda: self.send_button.configure(state="normal"))

    def load_codex_base_instructions(self) -> str:
        if self._codex_base_instructions_cache:
            return self._codex_base_instructions_cache
        # 1) Codex의 BASE_INSTRUCTIONS 로드
        base_content = ""
        candidate_paths = [
            os.path.join(os.getcwd(), 'codex', 'codex-rs', 'core', 'prompt.md'),
            os.path.join(os.path.dirname(__file__), 'codex', 'codex-rs', 'core', 'prompt.md')
        ]
        for path in candidate_paths:
            try:
                if os.path.isfile(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if content.strip():
                            base_content = content
                            print(f"[Codex] BASE_INSTRUCTIONS 로드됨: {path}")
                            break
            except Exception as e:
                print(f"[Codex] instructions 로드 실패({path}): {e}")
        # 사용자 instructions는 무시하고 Codex BASE만 사용
        if base_content:
            combined = base_content
        else:
            # 최종 폴백 (BASE가 없을 때만)
            print("[Codex] BASE_INSTRUCTIONS를 찾지 못해 최소 폴백 사용")
            combined = "You are a coding assistant. Be accurate, concise, and helpful."

        self._codex_base_instructions_cache = combined
        return combined

    def ensure_default_instructions_file(self):
        """(비활성) 사용자 instructions 파일은 사용하지 않음"""
        return

    # --- GUI Helpers ---
    def save_conversation(self):
        conversation_text = self.textbox.get("1.0", "end-1c")
        if not conversation_text.strip():
            self.status_label.configure(text="상태: 저장할 대화 내용이 없습니다.", text_color="orange")
            return

        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"chatlog_{timestamp}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(conversation_text)
            self.status_label.configure(text=f"상태: 대화가 '{filename}'으로 저장되었습니다.", text_color="green")
        except Exception as e:
            self.status_label.configure(text=f"상태: 파일 저장 중 오류 발생.", text_color="red")
            print(f"Failed to save conversation: {e}")

    def textbox_append(self, text):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", text)
        self.textbox.configure(state="disabled")
        self.textbox.see("end")

    # --- Loading indicator helpers ---
    def start_stream_loading(self):
        # 대화창에 로딩 플레이스홀더 추가하고 위치 저장
        self._loading_marker_index = self.textbox.index("end-1c")
        self.textbox_append("🤖 ChatGPT:  답변 생성중 ...\n")

    def finalize_stream_loading(self):
        # 로딩 텍스트를 제거하거나 개행만 남김
        try:
            if hasattr(self, "_loading_marker_index") and self._loading_marker_index:
                # 로딩 라인 삭제 (마지막 줄 기준)
                self.textbox.configure(state="normal")
                last_line = int(float(self.textbox.index("end-1c").split(".")[0]))
                self.textbox.delete(f"{last_line-1}.0", f"{last_line}.0")
                self.textbox.configure(state="disabled")
        except Exception:
            pass
        finally:
            self._loading_marker_index = None

    def textbox_stream_update(self, text_chunk):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", text_chunk)
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def update_status_post_capture(self):
        self.status_label.configure(text="🟢 상태: 세션 연결 완료!", text_color="#4ade80")
        self.textbox_append("\n✨ [시스템] 세션이 성공적으로 연결되었습니다. 이제 앱에서 대화할 수 있습니다.\n\n")

    def reset_login_ui(self):
        self.status_label.configure(text="🔴 상태: 세션 연결 실패", text_color="#f87171")
        self.login_button.configure(state="normal")

if __name__ == "__main__":
    app = App()
    app.mainloop()
