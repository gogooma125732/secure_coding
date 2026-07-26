# SAFER 연합 신원·Passkey 인증 경계

기준일: 2026-07-23

## 공급자와 계약 범위

SAFER에서 신원 공급자는 Sites 디스패처가 제공하는 **Sign in with ChatGPT(SIWC)** 다. 별도의 Auth0·Clerk·Firebase 계약이나 사용자 DB 위탁 없이, 디스패처가 확인한 ChatGPT 신원 헤더만 서버에서 사용한다. 이 경계는 SAFER가 임의의 이메일 헤더를 신뢰하는 구조가 아니라 Sites가 인증 후 전달하는 배포 플랫폼 경계에 의존한다.

Passkey에는 별도 인증 서비스 계약이 없다. 사용자의 운영체제·브라우저·보안키가 WebAuthn authenticator 역할을 하고 SAFER는 Relying Party(RP) 역할을 한다. 동기화형 Passkey를 선택한 경우 Apple·Google 등의 credential manager가 기기간 동기화를 제공할 수 있지만 SAFER가 그 서비스와 계약하거나 개인키를 전달하지 않는다.

## 가입과 로그인

1. 현재 소유자 전용 비공개 배포에서는 Sites 접근 정책이 방문자를 먼저 인증하고, SAFER는 디스패처가 전달한 인증 사용자 헤더를 서버에서 확인한다. 애플리케이션이 `/signin-with-chatgpt`로 다시 이동시키지 않는다.
2. SAFER는 전달된 신원을 독립 secret으로 HMAC 처리하여 `platform_identity_hash`만 저장한다.
3. 신규 계정은 동일 플랫폼 신원당 하나만 생성된다.
4. 연결된 사용자는 ChatGPT 연합 신원으로 SAFER 서버 세션을 발급받을 수 있다.
5. 로그인된 사용자는 ChatGPT 신원을 다시 확인한 뒤 최대 5개의 Passkey를 등록할 수 있다.
6. Passkey 로그인 성공 시 WebAuthn 응답을 서버에서 검증한 뒤 기존 HttpOnly·Secure SAFER 세션으로 교환한다.

기존 아이디·비밀번호 로그인은 마이그레이션 호환을 위해 유지한다. 신규 공개 운영에서는 연합 신원과 Passkey를 우선 노출하고 기존 비밀번호는 레거시 경로로 표시한다.

## Passkey 서버 검증

- RP ID와 HTTPS origin을 런타임 설정으로 고정하고 요청 origin과 다르면 거부한다.
- 등록과 로그인 challenge는 CSPRNG로 생성하고 D1에는 SHA-256 hash만 저장한다.
- challenge는 5분 후 만료되며 `DELETE ... RETURNING`으로 검증 전에 한 번만 소비한다.
- discoverable credential과 `userVerification: required`를 사용한다.
- attestation은 개인정보 최소화를 위해 `none`으로 요청한다.
- ES256과 RS256만 허용한다.
- D1에는 credential ID, COSE 공개키, 서명 카운터, transport, 백업·기기 유형만 저장한다.
- 개인키·생체정보·ChatGPT 토큰·원문 이메일은 SAFER에 저장하지 않는다.
- 등록·삭제에는 SAFER 세션, CSRF, 동일 origin과 연결된 ChatGPT 신원을 모두 요구한다.

## 공개 전환 조건

Sites 접근 정책을 공개로 바꾸기 전에 다음 조건을 확인한다.

- 공개 전환 시에는 익명 사용자는 읽기만 가능하게 하고, 가입·로그인 진입점은 Sites가 지원하는 SIWC 경계로 별도 전환한다. 비공개 배포용 UI를 그대로 공개하지 않는다.
- `/api/auth/platform-identity`가 익명과 인증 사용자를 구분한다.
- `PLATFORM_IDENTITY_SECRET`, `PASSKEY_RP_ID`, `PASSKEY_ORIGIN`이 운영 런타임에 설정되어 있다.
- 실제 도메인 변경 시 기존 Passkey가 새 RP ID에서 작동하지 않으므로 도메인을 먼저 확정한다.
- 복구용 Passkey 두 개 등록을 권장하고, 연합 신원 계정 복구를 최종 복구 경계로 문서화한다.

## 표준 OIDC로의 확장

Sites가 외부 OIDC Core 콜백을 앱에 직접 노출하지 않는 현재 배포에서는 SIWC가 지원되는 연합 신원 경계다. 향후 공급자 중립 OIDC가 반드시 필요하면 `issuer + subject`를 HMAC 가명화하는 동일한 계정 키에 연결하고 Authorization Code + PKCE, `state`, `nonce`, 서명·issuer·audience·만료 검증을 추가한다. 이메일은 계정 키로 사용하지 않는다.
