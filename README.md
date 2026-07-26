# SAFER — Secure Second-hand Marketplace

secure coding 중심 중고거래 플랫폼입니다.
회원가입, 상품 관리, 채팅, 신고, hash ID 기반 송금, 상품 거래 결제와 관리자 운영 기능을 제공합니다.

> 이 저장소에는 비밀번호, 지갑 seed, 세션, API 토큰, 실제 환경변수와 운영 데이터가 포함되어 있지 않습니다.

## 주요 기능

- Sites/ChatGPT 연합 신원과 WebAuthn Passkey 기반 인증
- PBKDF2-SHA-256 비밀번호 해시와 서버 세션
- 상품 등록·검색·상세 조회·판매자 관리
- JPEG·PNG·WebP magic byte 검사와 5MB 업로드 제한
- 전체 채팅과 1:1 채팅
- 사용자·상품 신고 및 누적 신고 자동 조치
- 256비트 seed에서 파생한 `wlt_` hash ID 기반 지갑
- 원자적·멱등 송금과 자가 송금·중복 결제 방지
- 상품 구매 요청·승인·결제 상태 전이
- Ethereum 지갑 서명 연결과 고정가 에스크로 예제
- 관리자 전용 대시보드와 보안 감사 로그
- CSP nonce, 브라우저 보안 이벤트, 안전한 오류 응답

## 기술 구성

- Frontend: React 19, Next.js 16, Vinext, Vite
- Runtime: Cloudflare Workers
- Database: Cloudflare D1 / Drizzle ORM
- Object storage: Cloudflare R2
- Authentication: Sites/ChatGPT identity, WebAuthn Passkey
- Web3: Solidity, Foundry, OpenZeppelin, viem
- Security testing: Node test runner, ESLint, npm audit, CodeQL, OWASP ZAP

## 요구 환경

- Node.js 22.13 이상
- npm
- Docker: ZAP 검사를 실행할 때만 필요
- Foundry: 스마트 컨트랙트 테스트를 실행할 때만 필요
- D1과 R2를 사용할 수 있는 Cloudflare Workers 호환 환경

## 로컬 실행

```bash
git clone https://github.com/gogooma125732/secure_coding.git
cd secure_coding
npm ci
npm run setup:local
npm run dev
```

`setup:local`은 Cloudflare Worker가 로컬에서 읽는 `.dev.vars`에 서로 다른 256비트 난수를 생성하고 파일 권한을 소유자 전용으로 설정합니다. 이미 파일이 있으면 덮어쓰지 않습니다. 기본 로컬 주소는 개발 서버 출력에서 확인합니다.

`.dev.vars`를 변경한 뒤에는 개발 서버를 완전히 종료하고 다시 시작해야 합니다. 실제 secret을 `.env.example`에 작성하거나 Git에 커밋하면 안 됩니다.

## 환경변수

| 변수 | 필수 여부 | 용도 |
|---|---:|---|
| `ADMIN_BOOTSTRAP_TOKEN` | 최초 설정 | 최초 관리자 설정용 32자 이상 일회성 난수 |
| `BOT_PROTECTION_MODE` | 필수 | `adaptive` 권장 |
| `BOT_PROTECTION_SECRET` | 필수 | 자동화 방어 challenge HMAC secret |
| `PLATFORM_IDENTITY_SECRET` | 필수 | 플랫폼 신원 가명화 HMAC secret |
| `PASSKEY_RP_ID` | Passkey 사용 시 | 포트·스킴을 제외한 배포 호스트 |
| `PASSKEY_ORIGIN` | Passkey 사용 시 | HTTPS를 포함한 정확한 origin |
| `WEB3_CHAIN_ID` | Web3 사용 시 | `11155111` Sepolia 권장 |
| `WEB3_RPC_URL` | Web3 사용 시 | HTTPS Ethereum RPC URL |
| `WEB3_RPC_HOST_ALLOWLIST` | Web3 사용 시 | 허용 RPC 호스트 목록 |
| `WEB3_ESCROW_ADDRESS` | 정산 사용 시 | 배포한 에스크로 주소 |
| `WEB3_PAYMENT_TOKEN_ADDRESS` | 정산 사용 시 | 결제 토큰 주소 |
| `WEB3_CONFIRMATIONS` | Web3 사용 시 | 필요한 확인 블록 수 |

각 secret은 서로 다른 고엔트로피 난수로 생성하고 호스팅 환경의 secret 저장소에서만 관리합니다.

## 데이터 바인딩과 마이그레이션

`.openai/hosting.json`에는 비밀값이 아니라 논리적 바인딩 이름만 저장합니다.

- D1: `DB`
- R2: `UPLOADS`
- 마이그레이션: `drizzle/*.sql`
- 스키마: `db/schema.ts`

스키마 변경 시 다음 순서를 따릅니다.

```bash
npm run db:generate
npm test
```

생성된 SQL을 검토한 뒤 배포하며, 이미 운영 환경에 적용된 마이그레이션은 수정하지 않습니다.

## 관리자 최초 설정

관리자 계정은 소스코드나 마이그레이션에 하드코딩하지 않습니다.

1. 32자 이상의 일회성 `ADMIN_BOOTSTRAP_TOKEN`을 런타임 secret으로 설정합니다.
2. 첫 일반 계정을 생성합니다.
3. 동일 출처의 `/api/admin/bootstrap`에 대상 username을 전달하고 `x-admin-bootstrap-token` 헤더로 일회성 토큰을 제출합니다.
4. 성공 후 `ADMIN_BOOTSTRAP_TOKEN`을 즉시 제거하거나 회전합니다.
5. `admin.bootstrapped` 감사 로그를 확인합니다.

이미 관리자가 존재하면 bootstrap 요청은 거부됩니다.

## 품질 및 보안 검사

```bash
npx tsc --noEmit
npm run lint
npm run security:check
npm test
```

`security:check`는 lockfile의 HTTPS registry와 SHA-512 무결성을 확인하고, 프로덕션 의존성에서 High 이상 취약점이 발견되면 실패합니다.

### OWASP ZAP

```bash
npm run dev
npm run security:zap:baseline
ZAP_ALLOW_ACTIVE_SCAN=local-only npm run security:zap:active
```

Active Scan은 스크립트 수준에서 localhost 대상으로 제한됩니다. 운영·공유 환경을 대상으로 능동 공격 검사를 실행하지 마세요.

### CodeQL과 Dependabot

- `.github/workflows/security.yml`: 빌드·테스트·의존성 검사와 CodeQL 분석
- `.github/dependabot.yml`: npm 및 GitHub Actions 주간 업데이트

CodeQL 경보가 발생하면 수정 또는 오탐 근거를 기록한 뒤 병합합니다.

## 보안 설계 문서

- [OWASP API Security Top 10:2023 및 OWASP Top 10:2025 통제표](docs/security/owasp-coverage.md)
- [인증 아키텍처](docs/security/authentication-architecture.md)
- [스마트 컨트랙트 위협 모델](docs/security/smart-contract-threat-model.md)
- [유지보수 절차](docs/maintenance.md)
- [보안 취약점 신고 정책](SECURITY.md)

## 주요 보안 원칙

- 클라이언트 입력과 권한을 신뢰하지 않고 서버에서 다시 검증합니다.
- SQL은 prepared statement와 bind만 사용합니다.
- 로그인 ID, 공개 별칭, 거래별 별칭과 지갑 ID를 분리합니다.
- 지갑 seed와 Passkey 개인키를 서버에 저장하지 않습니다.
- 송금과 상품 결제는 DB 제약, 상태 전이와 idempotency를 함께 사용합니다.
- API 오류는 내부 스택과 SQL을 노출하지 않고 요청 ID만 반환합니다.
- secret 미설정이나 외부 검증 실패 시 fail-closed 합니다.

## 알려진 제한사항

- 외부 CAPTCHA를 사용하지 않아 사람이 개입한 고도화된 자동화는 완전히 차단할 수 없습니다.
- 인증된 사용자별 ZAP 검사는 별도의 테스트 계정과 ZAP context가 필요합니다.
- Ethereum mainnet 배포 전에는 독립적인 스마트 컨트랙트 감사를 수행해야 합니다.
- 플랫폼 신원 기반 비공개 배포는 호스팅 제공자의 인증 경계에 의존합니다.

## 공개 저장소 주의사항

다음 항목은 절대 커밋하지 않습니다.

- `.env`, `.env.local`, `.dev.vars`
- 비밀번호, 지갑 seed, 개인키, 세션·CSRF 쿠키
- Sites/GitHub/API 토큰과 SIWC 우회 토큰
- 운영 DB 덤프, 실제 사용자 이메일과 로그
- ZAP 인증 context 및 테스트 계정 비밀번호

보안 문제를 발견했다면 공개 Issue에 공격 절차나 secret을 올리지 말고 [SECURITY.md](SECURITY.md)의 비공개 신고 절차를 이용해 주세요.

## 라이선스 및 용도

교육용 프로젝트입니다. 실제 자산을 처리하는 운영 서비스나 Ethereum mainnet에 사용하기 전 별도의 보안 검토와 법적 검토가 필요합니다.
