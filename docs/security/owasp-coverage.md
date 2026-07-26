# SAFER OWASP 방어 통제표

기준일: 2026-07-24

이 문서는 OWASP API Security Top 10:2023과 OWASP Top 10:2025를 SAFER의 실제 방어 통제에 연결한다. Top 10 준수는 취약점이 전혀 없다는 보증이 아니며, 배포 전후의 침투 테스트·의존성 점검·로그 모니터링을 계속 수행해야 한다.

## OWASP API Security Top 10:2023

| 항목 | 적용된 방어 로직 | 검증 지점 |
|---|---|---|
| API1:2023 Broken Object Level Authorization | 상품 변경은 `seller_id`, 거래 조회·변경은 `buyer_id`/`seller_id`, 송금 조회는 당사자 ID를 SQL 조건에 포함한다. 존재하지만 권한이 없는 객체도 404로 응답한다. | API 라우트의 소유권 조건과 BOLA 회귀 테스트 |
| API2:2023 Broken Authentication | Sites/ChatGPT 연합 신원을 서버 헤더로 확인해 HMAC 가명화하고 신원당 계정 하나만 허용한다. WebAuthn Passkey는 RP ID·origin·일회용 challenge·사용자 확인·서명 카운터를 검증한다. 기존 비밀번호에는 PBKDF2-SHA-256과 로그인 잠금을 적용한다. 서버 세션은 토큰을 해시 저장하고 8시간 절대 만료·30분 유휴 만료·새 로그인 시 기존 세션 폐기·만료 쿠키 삭제를 강제한다. | `requirePlatformIdentity`, `lib/passkeys.ts`, `createSession`, `requireSession`, 인증 테스트 |
| API3:2023 Broken Object Property Level Authorization | 모든 JSON 명령은 허용 필드 목록을 선언하며, 알 수 없는 속성은 `UNKNOWN_FIELD`로 거부한다. 로그인 아이디는 본인과 관리자에게만 반환하고 상품·채팅에는 무작위 공개 별칭, 상품 거래에는 거래별 별칭을 사용한다. 상품 결제 내역은 상대 지갑 주소를 반환하지 않는다. | `readJson(..., allowedFields)`와 식별자 최소화 DTO 테스트 |
| API4:2023 Unrestricted Resource Consumption | API 전체, 인증, 메시지, 신고, 상품, 송금에 원자적 속도 제한을 적용한다. JSON 32KB, 이미지 5MB, 결과 행 수, 검색 길이, 외부 응답 크기와 시간을 제한한다. IP 순환으로 `rate_limits`가 무한 증가하지 않도록 2일 보존기간의 확률적 정리도 수행한다. | `rate_limits`, `retry-after`, 보존기간·크기 제한 테스트 |
| API5:2023 Broken Function Level Authorization | 관리자 함수는 세션 확인 후 `requireAdmin`을 통과해야 한다. 사용자 상태·상품·신고·메시지 관리 API는 일반 사용자에게 노출되지 않는다. | 관리자 API 권한 검사 |
| API6:2023 Unrestricted Access to Sensitive Business Flows | 신고·가입 신원·지갑 생성·구매 요청·송금·결제에 개별 한도를 둔다. 송금과 상품 결제는 중복 방지 키, DB 제약, 상태 전이 조건을 사용한다. | D1 트리거와 idempotency 테스트 |
| API7:2023 Server Side Request Forgery | 가입 과정은 이메일 발송 등 외부 URL을 호출하지 않는다. 사용자가 서버 호출 URL을 지정할 수 없으며 Ethereum RPC는 HTTPS와 운영 allowlist를 모두 통과해야 한다. | 외부 URL 입력 부재와 RPC allowlist 테스트 |
| API8:2023 Security Misconfiguration | HSTS, 요청별 nonce CSP, frame 차단, MIME sniffing 차단, 권한 정책, 교차 출처 리소스 정책을 전역 적용하고 서버 식별 헤더를 제거한다. 운영 `connect-src`는 same-origin만 허용하고 개발용 WebSocket은 HTTP localhost에서만 허용한다. API는 `no-store`다. | Worker 헤더 테스트 |
| API9:2023 Improper Inventory Management | 단일 `/api` 라우터가 지원 경로와 HTTP 메서드를 명시하며, 그 외 경로는 동일한 404로 종료한다. 응답에는 `X-API-Version: 1`을 부여한다. | 라우트 목록과 Worker 헤더 |
| API10:2023 Unsafe Consumption of APIs | 외부 API 응답을 신뢰하지 않고 상태·크기·구조를 확인한다. 비밀키는 런타임 secret에서만 읽고, 오류 본문이나 인증정보를 로그에 남기지 않는다. | Sites 신원 헤더·Ethereum RPC 어댑터 테스트 |

## OWASP Top 10:2025

| 항목 | 적용된 방어 로직 | 검증 지점 |
|---|---|---|
| A01:2025 Broken Access Control | 기본 거부 방식의 세션·CSRF·역할·객체 소유권 검사를 서버에서 수행하고 교차 출처 변경 요청을 차단한다. 변경 요청은 정확한 `Origin`, 같은 출처 `Referer`, Fetch Metadata를 교차 확인하며 브라우저 요청에서 출처 증거가 없으면 거부한다. | `requireSession`, `requireAdmin`, `validateSameOrigin`, 소유권 SQL |
| A02:2025 Security Misconfiguration | 보안 헤더, 비공개 배포, API 캐시 금지, 신뢰 호스트 기반 메타데이터 URL, 안전한 오류 응답, 운영 테스트 키 거부, secret 미설정 시 fail-closed를 적용한다. | Worker·메타데이터 호스트·환경 설정 테스트 |
| A03:2025 Software Supply Chain Failures | 의존성 수를 최소화하고 lockfile v3, HTTPS npm registry, SHA-512 무결성을 자동 검사한다. `npm audit`의 high 이상을 배포 차단 조건으로 둔다. | `npm run security:check` |
| A04:2025 Cryptographic Failures | Web Crypto CSPRNG, PBKDF2 버전·work factor, SHA-256 토큰 해시, HMAC-SHA-256 플랫폼 신원 가명화, WebAuthn 비대칭 서명, HTTPS/HSTS, HttpOnly·Secure 쿠키를 사용한다. 원문 비밀번호·세션·Sites 이메일·Passkey 개인키는 저장하지 않는다. | 암호·쿠키·Passkey DB 스키마 테스트 |
| A05:2025 Injection | 모든 SQL은 prepared statement와 bind를 사용한다. 입력은 길이·형식·정수 범위를 검증하며 React의 기본 출력 인코딩을 유지하고 업로드는 magic byte를 확인한다. | API·업로드 테스트 |
| A06:2025 Insecure Design | 잔액·거래·신고 자동 조치는 DB 제약과 상태 전이로 설계한다. 신규 계정 잔액은 0이며 내부 거래 지갑과 검증된 Ethereum 지갑이 모두 연결되어도 임의 금액을 지급하지 않고 0원에서 시작한다. 자가 송금·자가 거래·중복 결제·식별자 상관관계를 애플리케이션과 DB 양쪽에서 제한한다. | D1 CHECK·UNIQUE·trigger·지갑 활성화 테스트 |
| A07:2025 Authentication Failures | Sites가 주입한 ChatGPT 연합 신원을 통과해야 신규 계정을 생성하고, 연결된 신원으로 서버 세션을 발급한다. Passkey 로그인은 discoverable credential, 사용자 확인 필수, 5분 challenge, 재사용 방지, 고정 RP ID와 origin을 적용한다. 기존 가입·비밀번호 경로에는 서명된 위험 기반 봇 방어를 유지한다. | 연합 신원·Passkey·자동화 방어 회귀 테스트 |
| A08:2025 Software or Data Integrity Failures | 대량 속성 할당을 거부하고, lockfile·업로드 내용·거래 상태·idempotency를 검증한다. 감사 로그 메타데이터는 민감 키를 자동 마스킹한다. | 무결성·감사 로그 테스트 |
| A09:2025 Security Logging and Alerting Failures | 로그인 실패, 속도 제한, 가입 신원 충돌, honeypot·변조·고위험 자동화 요청을 감사 로그에 남긴다. 관리 화면은 최근 24시간 보안 이벤트를 집계해 경보로 표시하며 모든 서버 오류에 요청 추적 ID를 붙인다. | 관리자 summary와 오류 테스트 |
| A10:2025 Mishandling of Exceptional Conditions | 중앙 오류 처리기가 내부 예외·스택·SQL 메시지를 숨기고 오류 종류와 요청 ID만 기록한다. 잘못된 percent-encoding 쿠키·이미지 경로는 500 대신 무시 또는 404로 종료한다. 외부 서비스는 timeout·크기 제한·fail-closed를 사용하고 파일/DB 실패 시 보상 정리를 수행한다. Ethereum 공급자 오류는 승인 취소·중복 요청·네트워크 단절처럼 사용자가 복구할 수 있는 원인만 분류해 안내한다. | `handleError`, `parseCookies`, `getImage`, 지갑 오류 매핑, 업로드 정리 테스트 |

## 운영 필수 조건

- `BOT_PROTECTION_MODE=adaptive`: 서버 서명형 위험 기반 자동화 방어를 활성화한다.
- `BOT_PROTECTION_SECRET`: 32자 이상의 독립 난수 secret. 도전값 HMAC 서명에만 사용하며 순환 교체 시 발급된 도전값은 만료된다.
- `PLATFORM_IDENTITY_SECRET`: 32자 이상의 독립 난수 secret. Sites/ChatGPT 로그인 신원을 HMAC 가명화할 때만 사용한다. 교체하면 기존 신원과 신규 가입 요청의 동일성 비교가 끊기므로 계획된 계정 재연결 절차 없이 임의로 순환하지 않는다.
- `PASSKEY_RP_ID`: Passkey가 결합될 실제 배포 호스트 이름. 포트·스킴·경로를 포함하지 않는다.
- `PASSKEY_ORIGIN`: `https://`를 포함한 정확한 SAFER origin. 요청 origin과 일치하지 않으면 Passkey 처리를 fail-closed 한다.
- 사이트 접근 정책은 비공개 상태로 유지한다. 공개 배포로 전환할 경우 신뢰할 수 있는 플랫폼 신원 헤더가 보장되지 않으므로 Passkey나 별도 OIDC 공급자를 먼저 도입한다.
- 관리자 화면의 보안 경보와 Worker 로그를 운영자가 정기적으로 확인하고, 반복되는 경보는 외부 알림 체계로 연결한다.

## 잔여 위험과 검증 범위

- 외부 CAPTCHA를 사용하지 않으므로 고도화된 사람이 개입한 자동화는 완전히 차단할 수 없다. 계정·플랫폼 신원·IP별 제한, 일회용 도전값, 로그인 잠금, 신규 계정 기능 제한과 운영 경보를 함께 유지해야 한다.
- Passkey 복구 강도는 ChatGPT 연합 신원 계정의 복구 정책에 영향을 받는다. 서로 다른 기기에 Passkey 두 개를 등록하고, Passkey 등록·삭제 시 연결된 ChatGPT 신원을 다시 확인해야 한다.
- 스크립트와 `<style>` 블록 CSP는 요청별 128비트 nonce를 사용하며, 스크립트에는 `strict-dynamic`을 적용한다. React 스트리밍이 내부 전송 노드에 생성하는 제한된 `style` 속성만 `style-src-attr 'unsafe-inline'`로 허용하고 애플리케이션 코드는 인라인 스타일을 만들지 않는다. Report-Only 정책은 Trusted Types 위반까지 수집한다.
- 운영 CSP의 `connect-src`는 `'self'`로 제한한다. HMR에 필요한 `ws:`/`wss:`는 HTTP localhost 개발 환경에서만 추가하므로 악성 스크립트가 임의 WebSocket으로 데이터를 반출할 수 있는 범위를 줄였다.
- API `OPTIONS`는 전역 메서드 목록을 노출하지 않고 실제 경로별 허용 메서드만 `Allow` 헤더로 반환하며, 존재하지 않는 경로는 404로 종료한다.
- React 렌더 오류, 전역 스크립트 오류, 처리되지 않은 Promise, CSP 위반은 크기·빈도·민감정보 제한을 거쳐 감사 로그에 기록한다. CSP 보고 원문과 nonce는 저장하지 않는다.
- 로그인 아이디, 마켓 공개 별칭, 상품 거래별 별칭, 내부 hash 지갑, Ethereum 주소를 서로 다른 식별자 영역으로 분리한다. 직접 송금은 사용자가 명시적으로 입력한 hash 지갑만 표시하고, 상품 결제는 거래별 별칭만 반환한다. 관리자의 실제 매핑 조회는 감사 로그에 남긴다.
- OWASP ZAP baseline 및 localhost 전용 active scan 구성을 제공한다. 인증된 권한별 스캔은 테스트 계정과 자동 인증 context를 추가해야 한다.
- 2026-07-23 배포 전 점검에서 발견된 Next.js·PostCSS·sharp·ws 전이 의존성 경고는 각각 16.2.11·8.5.14·0.35.0·8.21.0으로 고정해 보완했다. 2026-07-24 최종 점검에서는 lockfile 무결성, TypeScript, ESLint, 빌드, 소스 회귀 테스트를 통과했다. 현재 격리 실행환경에서는 npm registry DNS 접근이 차단되어 `npm audit`을 다시 조회하지 못했으므로, GitHub Actions의 audit·Dependabot·CodeQL 결과를 최종 공급망 판정으로 사용한다.
- OWASP ZAP 구성과 차단 규칙은 저장소에 포함했지만 현재 실행환경에는 Docker가 없어 이번 로컬 점검에서 ZAP 컨테이너를 실행하지 못했다. 배포 URL에는 안전한 baseline만, active scan은 승인된 localhost 테스트 대상에만 수행해야 한다.
- Top 10 매핑은 위험 우선순위 통제표다. SAST/DAST, 권한별 API 침투 테스트, 공급망 서명 검증, 비밀키 순환과 복구 훈련을 대체하지 않는다.

## 공식 기준

- https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- https://owasp.org/Top10/
