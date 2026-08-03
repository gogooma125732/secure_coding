"use client";

import { ChangeEvent, FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

const MAX_CLIENT_IMAGE_BYTES = 5 * 1024 * 1024;
const ALLOWED_CLIENT_IMAGE_TYPES = new Set(["image/jpeg", "image/png", "image/webp"]);
const ALLOWED_CLIENT_IMAGE_EXTENSIONS = new Set(["jpg", "jpeg", "png", "webp"]);
type Eip1193Provider = {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
};

declare global {
  interface Window { ethereum?: Eip1193Provider }
}

type View = "home" | "login" | "signup" | "market" | "new-product" | "product" | "profile" | "wallet" | "privacy" | "admin";
type User = { id: string; username: string; publicAlias: string; bio: string; role: "user" | "admin"; status: string; balance: number | null; walletReady: boolean };
type ListedUser = { id: string; alias: string; bio: string };
type Wallet = { id: string; createdAt: number };
type Web3Config = {
  chainId: 1 | 11155111;
  chainName: string;
  escrowAddress: string | null;
  paymentTokenAddress: string | null;
  walletLinkEnabled: boolean;
  settlementEnabled: boolean;
  confirmations: number;
};
type LinkedWeb3Wallet = { address: string; accountKind: "eoa" | "contract"; verifiedAt: number; createdAt: number };
type Product = {
  id: string;
  name: string;
  description: string;
  price: number;
  imageUrl: string;
  status: string;
  createdAt?: number;
  seller: { id: string; alias: string; bio?: string };
};
type Message = { id: string; body: string; created_at: number; sender_id: string; sender_alias: string };
type Transfer = {
  id: string;
  amount: number;
  memo: string;
  created_at: number;
  direction: "sent" | "received";
  peer_wallet_id: string | null;
  peer_alias: string | null;
  product_trade_id: string | null;
};
type ProductTrade = {
  id: string;
  productId: string;
  productName: string;
  productImageUrl: string;
  counterpartyAlias: string;
  price: number;
  status: "requested" | "accepted" | "completed" | "cancelled";
  transferId: string | null;
  createdAt: number;
  updatedAt: number;
  role: "buyer" | "seller";
};
type AdminUser = { id: string; username: string; bio: string; role: string; status: string; balance: number; created_at: number };
type AdminProduct = { id: string; name: string; price: number; status: string; created_at: number; seller_username: string };
type AdminReport = { id: string; target_type: string; target_id: string; reason: string; status: string; created_at: number; reporter_username: string };
type AdminLog = { id: string; actor_id: string | null; action: string; target_type: string; target_id: string | null; metadata: string; created_at: number };
type AdminTransfer = { id: string; amount: number; memo: string; created_at: number; sender_wallet_id: string | null; recipient_wallet_id: string | null; sender_username: string; recipient_username: string };
type AdminMessage = { id: string; body: string; created_at: number; sender_username: string; recipient_username: string | null };
type SecurityAlert = { action: string; count: number; last_seen_at: number };
type AdminData = { users: AdminUser[]; products: AdminProduct[]; reports: AdminReport[]; transferStats: { count: number; total: number } | null; transfers: AdminTransfer[]; messages: AdminMessage[]; logs: AdminLog[]; securityAlerts: SecurityAlert[] };
type PlatformIdentity = { authenticated: boolean; accountLinked: boolean; provider: "chatgpt-siwc" };
type PasskeySummary = { id: string; name: string; deviceType: string; backedUp: boolean; createdAt: number; lastUsedAt: number | null };

export function MarketplaceApp({ view, resourceId }: { view: View; resourceId?: string }) {
  const [user, setUser] = useState<User | null>(null);
  const [sessionReady, setSessionReady] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const refreshSession = useCallback(async () => {
    try {
      const data = await api<{ user: User | null }>("/api/auth/me");
      setUser(data.user);
    } finally {
      setSessionReady(true);
    }
  }, []);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  async function logout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
      window.location.assign("/");
    } catch (error) {
      setNotice(errorMessage(error));
    }
  }

  const isAdminConsole = view === "admin";

  return (
    <div className={isAdminConsole ? "site-shell admin-site-shell" : "site-shell"}>
      <a className="skip-link" href="#main">본문으로 건너뛰기</a>
      {!isAdminConsole ? <Header user={user} sessionReady={sessionReady} onLogout={logout} /> : null}
      {notice ? <div className="global-notice" role="status">{notice}<button onClick={() => setNotice(null)} aria-label="알림 닫기">×</button></div> : null}
      <main id="main">
        {view === "home" ? <Home user={user} /> : null}
        {view === "login" ? <AuthForm mode="login" onSuccess={refreshSession} /> : null}
        {view === "signup" ? <AuthForm mode="signup" onSuccess={refreshSession} /> : null}
        {view === "market" ? <Market user={user} sessionReady={sessionReady} /> : null}
        {view === "new-product" ? <NewProduct user={user} sessionReady={sessionReady} /> : null}
        {view === "product" && resourceId ? <ProductDetail id={resourceId} user={user} onUserChange={setUser} /> : null}
        {view === "profile" ? <Profile user={user} sessionReady={sessionReady} onUserChange={setUser} /> : null}
        {view === "wallet" ? <WalletCenter user={user} sessionReady={sessionReady} onUserChange={setUser} /> : null}
        {view === "privacy" ? <PrivacyPolicy /> : null}
        {view === "admin" ? <Admin user={user} sessionReady={sessionReady} onLogout={logout} /> : null}
      </main>
      {!isAdminConsole ? <Footer /> : null}
    </div>
  );
}

function Header({ user, sessionReady, onLogout }: { user: User | null; sessionReady: boolean; onLogout: () => void }) {
  return (
    <header className="topbar">
      <a className="brand" href="/" aria-label="SAFER 홈">
        <span className="brand-mark" aria-hidden="true">S</span>
        <span>SAFER<small>secure secondhand</small></span>
      </a>
      <nav aria-label="주요 메뉴">
        <a href="/market">마켓</a>
        {user ? <a href="/products/new">상품 등록</a> : null}
        {user ? <a href="/profile">마이페이지</a> : null}
        {user ? <a href="/wallet">지갑·거래</a> : null}
        {user?.role === "admin" ? <a className="admin-nav-link" href="/admin"><span aria-hidden="true">◆</span> 관리자 대시보드</a> : null}
      </nav>
      <div className="account-actions">
        {!sessionReady ? <span className="session-loading">확인 중…</span> : user ? (
          <>
            {user.walletReady && user.balance !== null
              ? <a className="balance-pill" href="/wallet" aria-label={`보유 잔액 ${money(user.balance)}`}>{money(user.balance)}</a>
              : <a className="button ghost small" href="/wallet">지갑 연결</a>}
            <button className="button ghost small" onClick={onLogout}>로그아웃</button>
          </>
        ) : (
          <>
            <a className="button ghost small" href="/login">로그인</a>
            <a className="button primary small" href="/signup">가입하기</a>
          </>
        )}
      </div>
    </header>
  );
}

function Home({ user }: { user: User | null }) {
  const [products, setProducts] = useState<Product[]>([]);
  useEffect(() => {
    api<{ products: Product[] }>("/api/products").then((data) => setProducts(data.products.slice(0, 4))).catch(() => undefined);
  }, []);
  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow"><span /> SECURE BY DESIGN</p>
          <h1>좋은 거래는<br />신뢰에서 시작돼요.</h1>
          <p className="hero-lede">계정부터 송금, 신고와 채팅까지. 보안을 나중에 덧붙이지 않고 처음부터 설계한 중고거래 공간입니다.</p>
          <div className="hero-actions">
            <a className="button primary" href="/market">상품 둘러보기 <span aria-hidden="true">→</span></a>
            <a className="button ghost" href={user ? "/products/new" : "/signup"}>{user ? "내 물건 등록하기" : "안전하게 시작하기"}</a>
          </div>
          <dl className="trust-stats">
            <div><dt>3회</dt><dd>누적 신고 자동 차단</dd></div>
            <div><dt>100%</dt><dd>서버 권한 검증</dd></div>
            <div><dt>24/7</dt><dd>감사 기록 보존</dd></div>
          </dl>
        </div>
        <div className="hero-visual" aria-label="안전한 거래 흐름">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="shield-card">
            <span className="shield-lock" aria-hidden="true">●</span>
            <strong>거래 보호 중</strong>
            <small>모든 요청을 검증하고 있어요</small>
          </div>
          <div className="floating-card card-chat"><span>•••</span><b>안전한 채팅</b><small>메시지는 로그인 사용자만</small></div>
          <div className="floating-card card-pay"><span>₩</span><b>원자적 송금</b><small>중복·잔액 초과 방지</small></div>
          <div className="floating-card card-report"><span>!</span><b>커뮤니티 보호</b><small>신고 누적 자동 조치</small></div>
        </div>
      </section>
      <section className="section feature-strip" aria-labelledby="secure-features">
        <div className="section-heading"><div><p className="eyebrow"><span /> SAFETY LAYER</p><h2 id="secure-features">거래의 모든 순간을 지켜요</h2></div><p>보안 기능이 사용을 방해하지 않도록 자연스럽게 녹였습니다.</p></div>
        <div className="feature-grid">
          <article><i>01</i><span className="feature-icon">⌁</span><h3>검증된 계정</h3><p>느린 비밀번호 해시와 안전한 서버 세션으로 계정을 보호합니다.</p></article>
          <article><i>02</i><span className="feature-icon">↔</span><h3>안전한 송금</h3><p>데이터베이스가 잔액 확인과 양쪽 반영을 한 번에 처리합니다.</p></article>
          <article><i>03</i><span className="feature-icon">◎</span><h3>빠른 커뮤니케이션</h3><p>전체 채팅과 1:1 대화를 한 화면에서 이어갈 수 있습니다.</p></article>
          <article><i>04</i><span className="feature-icon">◇</span><h3>자동 커뮤니티 보호</h3><p>중복 신고를 막고 기준을 넘으면 즉시 노출과 접근을 차단합니다.</p></article>
        </div>
      </section>
      <section className="section latest-section">
        <div className="section-heading"><div><p className="eyebrow"><span /> JUST IN</p><h2>방금 등록된 상품</h2></div><a href="/market">전체 보기 →</a></div>
        {products.length ? <ProductGrid products={products} /> : <EmptyState title="첫 상품을 기다리고 있어요" body="회원가입 후 안전하게 상품을 등록해 보세요." />}
      </section>
    </>
  );
}

function AuthForm({ mode, onSuccess }: { mode: "login" | "signup"; onSuccess: () => Promise<void> }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [botChallenge, setBotChallenge] = useState("");
  const [botReady, setBotReady] = useState(false);
  const [platformIdentity, setPlatformIdentity] = useState<PlatformIdentity | null>(null);
  const [passkeyReady, setPasskeyReady] = useState(false);
  const isSignup = mode === "signup";

  const refreshBotChallenge = useCallback(async () => {
    setBotReady(false);
    setBotChallenge("");
    try {
      const result = await api<{ challengeToken: string }>(`/api/auth/bot-challenge?action=${mode}`);
      setBotChallenge(result.challengeToken ?? "");
      setBotReady(true);
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }, [mode]);

  useEffect(() => { void refreshBotChallenge(); }, [refreshBotChallenge]);
  useEffect(() => {
    api<PlatformIdentity>("/api/auth/platform-identity")
      .then(setPlatformIdentity)
      .catch((caught) => setError(errorMessage(caught)));
    setPasskeyReady(browserSupportsWebAuthn());
    if (!isSignup && new URLSearchParams(window.location.search).get("reason") === "session-expired") {
      setError("로그인 세션이 만료되었습니다. 다시 로그인해 주세요.");
    }
  }, [isSignup]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    if (!botReady) {
      setError("보안 확인을 준비하고 있습니다. 잠시 후 다시 시도해 주세요.");
      return;
    }
    setPending(true);
    const form = new FormData(event.currentTarget);
    try {
      const result = await api<{ user: User }>(`/api/auth/${isSignup ? "signup" : "login"}`, {
        method: "POST",
        body: JSON.stringify({
          username: form.get("username"),
          password: form.get("password"),
          bio: isSignup ? form.get("bio") ?? undefined : undefined,
          botChallenge,
          website: form.get("website"),
        }),
      });
      await onSuccess();
      window.location.assign(isSignup ? "/profile" : result.user.role === "admin" ? "/admin" : "/market");
    } catch (caught) {
      setError(errorMessage(caught));
      void refreshBotChallenge();
      setPending(false);
    }
  }

  async function loginWithPlatformIdentity() {
    setPending(true); setError("");
    try {
      const result = await api<{ user: User }>("/api/auth/platform-login", { method: "POST", body: "{}" });
      await onSuccess();
      window.location.assign(result.user.role === "admin" ? "/admin" : "/market");
    } catch (caught) {
      setError(errorMessage(caught));
      setPending(false);
    }
  }

  async function loginWithPasskey() {
    setPending(true); setError("");
    try {
      const start = await api<{ challengeId: string; options: PublicKeyCredentialRequestOptionsJSON }>(
        "/api/auth/passkeys/authentication/options",
        { method: "POST", body: "{}" },
      );
      const response = await startAuthentication({ optionsJSON: start.options });
      const result = await api<{ user: User }>("/api/auth/passkeys/authentication/verify", {
        method: "POST",
        body: JSON.stringify({ challengeId: start.challengeId, response }),
      });
      await onSuccess();
      window.location.assign(result.user.role === "admin" ? "/admin" : "/market");
    } catch (caught) {
      setError(errorMessage(caught));
      setPending(false);
    }
  }

  const showCredentialForm = !isSignup || (
    platformIdentity?.authenticated === true &&
    platformIdentity.accountLinked === false
  );
  return (
    <section className="auth-layout">
      <div className="auth-aside">
        <a className="brand light" href="/"><span className="brand-mark">S</span><span>SAFER<small>secure secondhand</small></span></a>
        <div><p className="eyebrow light"><span /> TRUST STARTS HERE</p><h1>{isSignup ? <>안전한 거래의<br />첫걸음을 시작해요.</> : <>다시 만나<br />반가워요.</>}</h1><p>Sites의 ChatGPT 연합 신원 경계와 피싱 저항형 Passkey를 함께 사용합니다. 원문 이메일은 저장하지 않고, 기존 비밀번호는 단방향 해시로만 보관합니다.</p></div>
        <ul className="auth-points"><li>ChatGPT 연합 신원 확인</li><li>WebAuthn Passkey 로그인</li><li>8시간·30분 유휴 만료 서버 세션</li><li>로그인·가입 시도 횟수 제한</li></ul>
      </div>
      <div className="auth-main">
        <div className="auth-card">
          <p className="step-label">{isSignup ? "CREATE ACCOUNT" : "WELCOME BACK"}</p>
          <h2>{isSignup ? "회원가입" : "로그인"}</h2>
          <p>{isSignup ? "ChatGPT 로그인 신원을 확인한 뒤 SAFER 계정을 생성합니다." : "연결된 신원이나 Passkey로 로그인하세요."}</p>
          {!isSignup ? <div className="auth-methods">
            {platformIdentity === null
              ? <p className="auth-method-note" role="status">현재 Sites/ChatGPT 접근 신원을 확인하고 있습니다…</p>
              : platformIdentity.authenticated && platformIdentity.accountLinked
                ? <button type="button" className="button primary wide" disabled={pending} onClick={() => void loginWithPlatformIdentity()}>확인된 ChatGPT 신원으로 계속</button>
                : platformIdentity.authenticated
                  ? <a className="button primary wide" href="/signup">이 ChatGPT 신원으로 SAFER 가입</a>
                  : <div className="adaptive-protection" role="alert"><span aria-hidden="true">!</span><p><strong>접근 신원을 확인할 수 없습니다</strong><small>허용된 ChatGPT 계정으로 이 비공개 사이트를 다시 열어 주세요.</small></p></div>}
            <button type="button" className="button ghost wide" disabled={pending || !passkeyReady} onClick={() => void loginWithPasskey()}>
              {passkeyReady ? "Passkey로 로그인" : "이 브라우저는 Passkey를 지원하지 않습니다"}
            </button>
            <p className="auth-method-note">비공개 Sites가 전달한 인증 신원만 사용하며 외부 인증 토큰은 저장하지 않습니다.</p>
          </div> : null}
          {isSignup && platformIdentity === null ? <div className="adaptive-protection" role="status"><span aria-hidden="true">…</span><p><strong>신원 경계 확인 중</strong><small>현재 ChatGPT 로그인 상태를 확인하고 있습니다.</small></p></div> : null}
          {isSignup && platformIdentity && !platformIdentity.authenticated ? <div className="auth-methods">
            <p>현재 비공개 Sites 접근 신원을 확인할 수 없습니다. 허용된 ChatGPT 계정으로 사이트를 다시 연 뒤 가입해 주세요.</p>
            <button type="button" className="button primary wide" onClick={() => window.location.reload()}>접근 신원 다시 확인</button>
          </div> : null}
          {isSignup && platformIdentity?.authenticated && platformIdentity.accountLinked ? <div className="auth-methods">
            <div className="adaptive-protection" role="status"><span aria-hidden="true">✓</span><p><strong>이미 연결된 계정이 있습니다</strong><small>현재 ChatGPT 신원은 기존 SAFER 계정과 연결되어 있습니다. 새 계정을 만들지 않고 기존 계정으로 로그인합니다.</small></p></div>
            <button type="button" className="button primary wide" disabled={pending} onClick={() => void loginWithPlatformIdentity()}>
              기존 SAFER 계정으로 로그인
            </button>
          </div> : null}
          {showCredentialForm ? <form onSubmit={submit}>
              {!isSignup ? <p className="auth-method-note">기존 계정만 아이디·비밀번호 로그인을 사용할 수 있습니다.</p> : null}
              <label>아이디<input name="username" autoComplete="username" minLength={3} maxLength={24} pattern="[A-Za-z0-9_]+" required placeholder="영문, 숫자, 밑줄 3–24자" /></label>
              <label>비밀번호<input name="password" type="password" autoComplete={isSignup ? "new-password" : "current-password"} minLength={12} maxLength={128} required placeholder="영문·숫자·특수문자 포함 12자 이상" /></label>
              {isSignup ? <label>소개글 <small>선택</small><textarea name="bio" maxLength={300} rows={3} placeholder="어떤 거래를 좋아하는지 알려주세요." /></label> : null}
              <div className="bot-trap" aria-hidden="true"><label>웹사이트<input name="website" tabIndex={-1} autoComplete="off" /></label></div>
              <div className="adaptive-protection" role="status"><span aria-hidden="true">✓</span><p><strong>위험 기반 요청 보호</strong><small>{botReady ? "요청 속도·재사용·비정상 입력을 서버에서 확인합니다." : "보안 확인을 준비하고 있습니다…"}</small></p></div>
              {error ? <p className="form-error" role="alert">{error}</p> : null}
              <button className="button primary wide" disabled={pending || !botReady}>{pending ? "안전하게 처리 중…" : isSignup ? "신원 확인 후 가입" : "기존 비밀번호로 로그인"}</button>
          </form> : null}
          {error && !showCredentialForm ? <p className="form-error" role="alert">{error}</p> : null}
          <p className="auth-switch">{isSignup ? "이미 계정이 있나요?" : "아직 계정이 없나요?"} <a href={isSignup ? "/login" : "/signup"}>{isSignup ? "로그인" : "회원가입"}</a></p>
        </div>
      </div>
    </section>
  );
}

function Market({ user, sessionReady }: { user: User | null; sessionReady: boolean }) {
  const [query, setQuery] = useState("");
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);

  const loadProducts = useCallback(async (search = "") => {
    setLoading(true);
    try {
      const data = await api<{ products: Product[] }>(`/api/products?q=${encodeURIComponent(search)}`);
      setProducts(data.products);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadProducts(); }, [loadProducts]);

  function search(event: FormEvent) {
    event.preventDefault();
    void loadProducts(query);
  }

  return (
    <section className="market-page">
      <div className="market-intro">
        <div><p className="eyebrow"><span /> MARKETPLACE</p><h1>필요한 물건을<br />안전하게 발견하세요.</h1></div>
        <form className="search-box" role="search" onSubmit={search}><label htmlFor="product-search">상품 검색</label><div><input id="product-search" value={query} onChange={(event) => setQuery(event.target.value)} maxLength={60} placeholder="상품명이나 설명으로 검색" /><button aria-label="검색">⌕</button></div></form>
      </div>
      <div className="market-layout">
        <div className="catalog">
          <div className="catalog-head"><h2>전체 상품 <span>{products.length}</span></h2>{user ? <a className="button primary small" href="/products/new">+ 새 상품 등록</a> : null}</div>
          {loading ? <LoadingCards /> : products.length ? <ProductGrid products={products} /> : <EmptyState title="검색 결과가 없어요" body="다른 검색어로 찾아보세요." />}
        </div>
        <ChatPanel user={user} sessionReady={sessionReady} />
      </div>
    </section>
  );
}

function ProductGrid({ products }: { products: Product[] }) {
  return <div className="product-grid">{products.map((product) => <a className="product-card" href={`/products/${product.id}`} key={product.id}><div className="product-image"><img src={product.imageUrl} alt="" loading="lazy" /><span>검증됨</span></div><div className="product-card-body"><p className="seller-name">{product.seller.alias}</p><h3>{product.name}</h3><strong>{money(product.price)}</strong></div></a>)}</div>;
}

function NewProduct({ user, sessionReady }: { user: User | null; sessionReady: boolean }) {
  const [preview, setPreview] = useState<string | null>(null);
  const [imageStatus, setImageStatus] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => () => {
    if (preview) URL.revokeObjectURL(preview);
  }, [preview]);
  if (!sessionReady) return <PageLoading />;
  if (!user) return <SignInRequired />;

  function selectImage(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0] ?? null;
    const validationError = validateProductImage(file);
    setError(validationError);
    if (!file || validationError) {
      event.currentTarget.value = "";
      setPreview(null);
      setImageStatus("");
      return;
    }
    setPreview(URL.createObjectURL(file));
    setImageStatus(`${file.name} · ${formatFileSize(file.size)} · 업로드 가능`);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const form = new FormData(event.currentTarget);
    const validationError = validateProductImage(form.get("image"));
    if (validationError) {
      setError(validationError);
      return;
    }
    setPending(true);
    try {
      const data = await api<{ product: Product }>("/api/products", { method: "POST", body: form });
      window.location.assign(`/products/${data.product.id}`);
    } catch (caught) {
      setError(errorMessage(caught));
      setPending(false);
    }
  }

  return (
    <section className="form-page">
      <div className="form-page-heading"><p className="eyebrow"><span /> NEW LISTING</p><h1>새 상품 등록</h1><p>정확한 정보와 실제 사진은 신뢰할 수 있는 거래의 시작입니다.</p></div>
      <form className="listing-form" onSubmit={submit}>
        <div className="image-upload">
          <label><input name="image" type="file" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" required aria-describedby="image-requirements image-status" onChange={selectImage} /><div className={`image-drop ${error ? "invalid" : ""}`}>{preview ? <img src={preview} alt="업로드할 상품 미리보기" /> : <><span>＋</span><strong>상품 사진 추가</strong><small>JPEG, PNG, WebP · 최대 5MB</small></>}</div></label>
          <div className="image-requirements" id="image-requirements"><strong>이미지 업로드 기준</strong><ul><li>허용 형식: JPEG(.jpg, .jpeg), PNG(.png), WebP(.webp)</li><li>최대 크기: 5MB</li><li>HEIC, GIF, SVG, 실행 파일은 등록할 수 없습니다.</li></ul></div>
          {imageStatus ? <p className="image-status" id="image-status" role="status">✓ {imageStatus}</p> : null}
        </div>
        <div className="listing-fields">
          <label>상품명<input name="name" minLength={2} maxLength={80} required placeholder="무엇을 판매하시나요?" /></label>
          <label>가격<div className="price-input"><span>₩</span><input name="price" inputMode="numeric" pattern="[0-9]+" min={1} max={1_000_000_000} required placeholder="0" /></div></label>
          <label>상품 설명<textarea name="description" minLength={10} maxLength={3000} rows={8} required placeholder="상태, 사용 기간, 거래 방법을 자세히 알려주세요." /></label>
          <div className="secure-tip"><span>✓</span><p><strong>파일을 안전하게 검사해요.</strong><br />확장자가 아닌 실제 파일 내용을 확인하며, 실행 가능한 이미지는 받지 않습니다.</p></div>
          {error ? <p className="form-error" role="alert">{error}</p> : null}
          <div className="form-actions"><a className="button ghost" href="/market">취소</a><button className="button primary" disabled={pending}>{pending ? "등록 중…" : "안전하게 등록하기"}</button></div>
        </div>
      </form>
    </section>
  );
}

function ProductDetail({ id, user, onUserChange }: { id: string; user: User | null; onUserChange: (user: User) => void }) {
  const [product, setProduct] = useState<Product | null>(null);
  const [error, setError] = useState("");
  const [reportOpen, setReportOpen] = useState(false);
  const [trade, setTrade] = useState<ProductTrade | null>(null);
  const [tradeFeedback, setTradeFeedback] = useState("");
  const [tradePending, setTradePending] = useState(false);
  const paymentRequestKey = useRef("");

  const loadTrade = useCallback(async () => {
    if (!user) { setTrade(null); return; }
    const data = await api<{ trades: ProductTrade[] }>(`/api/product-trades?productId=${encodeURIComponent(id)}`);
    setTrade(data.trades.find((item) => item.status !== "cancelled") ?? null);
  }, [id, user]);

  useEffect(() => {
    api<{ product: Product }>(`/api/products/${id}`).then((data) => setProduct(data.product)).catch((caught) => setError(errorMessage(caught)));
  }, [id]);
  useEffect(() => { void loadTrade().catch((caught) => setTradeFeedback(errorMessage(caught))); }, [loadTrade]);

  async function requestTrade() {
    setTradeFeedback(""); setTradePending(true);
    try {
      await api("/api/product-trades", { method: "POST", body: JSON.stringify({ productId: id }) });
      await loadTrade();
      setTradeFeedback("구매 요청을 보냈습니다. 판매자가 승인하면 지갑으로 결제할 수 있습니다.");
    } catch (caught) { setTradeFeedback(errorMessage(caught)); }
    finally { setTradePending(false); }
  }

  async function changeTrade(action: "accept" | "cancel") {
    if (!trade) return;
    setTradeFeedback(""); setTradePending(true);
    try {
      await api(`/api/product-trades/${trade.id}`, { method: "PATCH", body: JSON.stringify({ action }) });
      await loadTrade();
      setTradeFeedback(action === "accept" ? "구매 요청을 승인했습니다. 구매자의 결제를 기다립니다." : "상품 거래를 취소했습니다.");
    } catch (caught) { setTradeFeedback(errorMessage(caught)); }
    finally { setTradePending(false); }
  }

  async function payTrade() {
    if (!trade || tradePending) return;
    const idempotencyKey = paymentRequestKey.current || crypto.randomUUID();
    paymentRequestKey.current = idempotencyKey;
    setTradeFeedback(""); setTradePending(true);
    try {
      await api(`/api/product-trades/${trade.id}/pay`, { method: "POST", headers: { "idempotency-key": idempotencyKey } });
      paymentRequestKey.current = "";
      const [productData, session] = await Promise.all([api<{ product: Product }>(`/api/products/${id}`), api<{ user: User }>("/api/auth/me"), loadTrade()]);
      setProduct(productData.product);
      if (session.user) onUserChange(session.user);
      setTradeFeedback("상품 결제가 완료되었습니다. 지갑 거래 데이터에도 기록되었습니다.");
    } catch (caught) { setTradeFeedback(errorMessage(caught)); }
    finally { setTradePending(false); }
  }

  if (error) return <EmptyState title="상품을 표시할 수 없어요" body={error} />;
  if (!product) return <PageLoading />;
  const own = user?.id === product.seller.id;
  const sold = product.status === "sold";
  return (
    <section className="detail-page">
      <nav className="breadcrumbs" aria-label="현재 위치"><a href="/market">마켓</a><span>›</span><span>{product.name}</span></nav>
      <div className="detail-grid">
        <div className="detail-image"><img src={product.imageUrl} alt={`${product.name} 상품 사진`} /><span className="verified-badge">✓ 안전 검사 완료</span></div>
        <div className="detail-copy">
          <p className="seller-name">판매자 {product.seller.alias}</p><div className="product-title-row"><h1>{product.name}</h1>{sold ? <span className="status sold">거래 완료</span> : null}</div><strong className="detail-price">{money(product.price)}</strong>
          <div className="seller-card"><div className="avatar">{product.seller.alias.slice(4, 5).toUpperCase()}</div><div><b>{product.seller.alias}</b><p>{product.seller.bio || "소개글이 아직 없습니다."}</p></div>{user && !own ? <a className="button ghost small" href={`/market?direct=${product.seller.id}`}>1:1 대화</a> : null}</div>
          <div className="detail-actions">{own ? <a className="button ghost wide" href="/profile">내 상품 관리</a> : user ? <><a className="button ghost wide" href={`/market?direct=${product.seller.id}`}>판매자와 대화하기</a>{!sold ? <button className="button danger-icon" onClick={() => setReportOpen(true)} aria-label="상품 신고">!</button> : null}</> : <a className="button primary wide" href="/login">로그인하고 거래하기</a>}</div>
          {user ? <section className="product-trade-box" aria-label="상품 거래">
            <div><p className="step-label">PRODUCT TRADE</p><h2>지갑으로 상품 거래</h2><p>가격과 판매자 지갑은 서버가 다시 확인하며, 결제와 상품 판매 완료가 함께 처리됩니다.</p></div>
            {tradeFeedback ? <p className="inline-notice" role="status">{tradeFeedback}</p> : null}
            {!trade && !own && !sold ? user.walletReady
              ? <button className="button primary wide" disabled={tradePending} onClick={() => void requestTrade()}>{tradePending ? "요청 중…" : `${money(product.price)} 구매 요청`}</button>
              : <a className="button primary wide" href="/wallet">지갑 등록·계정 연결 후 거래하기</a> : null}
            {trade?.status === "requested" && trade.role === "seller" ? <div className="trade-action-row"><button className="button primary" disabled={tradePending} onClick={() => void changeTrade("accept")}>구매 요청 승인</button><button className="button ghost" disabled={tradePending} onClick={() => void changeTrade("cancel")}>거절</button></div> : null}
            {trade?.status === "requested" && trade.role === "buyer" ? <div className="trade-state"><span>1</span><div><b>판매자 승인 대기</b><small>승인 전에는 금액이 이동하지 않습니다.</small></div><button className="button text-danger small" disabled={tradePending} onClick={() => void changeTrade("cancel")}>요청 취소</button></div> : null}
            {trade?.status === "accepted" && trade.role === "buyer" ? <><div className="trade-state accepted"><span>2</span><div><b>판매자가 요청을 승인했습니다</b><small>결제 금액 {money(trade.price)} · 잔액과 지갑을 서버에서 검증합니다.</small></div></div><div className="trade-action-row"><button className="button primary" disabled={tradePending} onClick={() => void payTrade()}>{tradePending ? "결제 처리 중…" : "지갑으로 결제하기"}</button><button className="button ghost" disabled={tradePending} onClick={() => void changeTrade("cancel")}>거래 취소</button></div></> : null}
            {trade?.status === "accepted" && trade.role === "seller" ? <div className="trade-state accepted"><span>2</span><div><b>구매자 결제 대기</b><small>결제가 완료되면 판매 대금이 내 지갑으로 입금됩니다.</small></div><button className="button text-danger small" disabled={tradePending} onClick={() => void changeTrade("cancel")}>거래 취소</button></div> : null}
            {trade?.status === "completed" ? <div className="trade-state completed"><span>✓</span><div><b>상품 거래 완료</b><small>{money(trade.price)} 결제와 수금이 거래 데이터에 연결되었습니다.</small></div><a className="button ghost small" href="/wallet">거래 데이터 보기</a></div> : null}
            {own && !trade && !sold ? <p className="trade-helper">구매 요청이 도착하면 이 화면과 지갑·거래 탭에서 승인할 수 있습니다.</p> : null}
          </section> : null}
          <div className="assurance-row"><span>✓ 서버 권한 확인</span><span>✓ 안전한 이미지</span><span>✓ 신고 보호</span></div>
        </div>
      </div>
      <article className="product-description"><p className="eyebrow"><span /> DESCRIPTION</p><h2>상품 설명</h2><p>{product.description}</p></article>
      {reportOpen && user && !own && !sold ? <ReportDialog targetType="product" targetId={product.id} label={product.name} onClose={() => setReportOpen(false)} /> : null}
    </section>
  );
}

function ChatPanel({ user, sessionReady }: { user: User | null; sessionReady: boolean }) {
  const [mode, setMode] = useState<"group" | "direct">("group");
  const [messages, setMessages] = useState<Message[]>([]);
  const [users, setUsers] = useState<ListedUser[]>([]);
  const [selected, setSelected] = useState<ListedUser | null>(null);
  const [userQuery, setUserQuery] = useState("");
  const [reportUser, setReportUser] = useState<ListedUser | null>(null);
  const directFromUrl = useMemo(() => typeof window === "undefined" ? "" : new URLSearchParams(window.location.search).get("direct") ?? "", []);

  const loadMessages = useCallback(async () => {
    if (!user) return;
    const endpoint = mode === "group" ? "/api/chat/group" : selected ? `/api/chat/direct?userId=${selected.id}` : null;
    if (!endpoint) return;
    try {
      const data = await api<{ messages: Message[] }>(endpoint);
      setMessages(data.messages);
    } catch {
      // Polling errors are retried on the next interval without disrupting typing.
    }
  }, [mode, selected, user]);

  useEffect(() => {
    if (!user) return;
    void loadMessages();
    const timer = window.setInterval(() => void loadMessages(), 2000);
    return () => window.clearInterval(timer);
  }, [loadMessages, user]);

  useEffect(() => {
    if (!user || mode !== "direct") return;
    api<{ users: ListedUser[] }>(`/api/users?q=${encodeURIComponent(userQuery)}`).then((data) => {
      setUsers(data.users);
      if (directFromUrl && !selected) {
        const match = data.users.find((candidate) => candidate.id === directFromUrl);
        if (match) setSelected(match);
      }
    }).catch(() => undefined);
  }, [user, mode, userQuery, directFromUrl, selected]);

  async function send(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!user || (mode === "direct" && !selected)) return;
    const form = event.currentTarget;
    const formData = new FormData(form);
    const message = String(formData.get("message") ?? "");
    if (!message.trim()) return;
    await api(`/api/chat/${mode}`, { method: "POST", body: JSON.stringify({ message, userId: selected?.id }) });
    form.reset();
    await loadMessages();
  }

  return (
    <aside className="chat-panel" aria-label="채팅">
      <div className="chat-head"><div><span className="online-dot" /><strong>대화</strong><small>2초마다 새 메시지 확인</small></div><span className="lock-label">보호됨</span></div>
      <div className="chat-tabs"><button className={mode === "group" ? "active" : ""} onClick={() => { setMode("group"); setMessages([]); }}>전체 채팅</button><button className={mode === "direct" ? "active" : ""} onClick={() => { setMode("direct"); setMessages([]); }}>1:1 채팅</button></div>
      {!sessionReady ? <div className="chat-empty">세션 확인 중…</div> : !user ? <div className="chat-empty"><span>◎</span><strong>로그인 후 대화할 수 있어요</strong><p>안전한 커뮤니티를 위해 참여자는 계정 확인이 필요합니다.</p><a className="button primary small" href="/login">로그인</a></div> : (
        <>
          {mode === "direct" ? <div className="direct-picker"><input value={userQuery} onChange={(event) => setUserQuery(event.target.value)} placeholder="공개 별칭으로 사용자 검색" maxLength={40} />{!selected ? <div className="user-results">{users.map((candidate) => <button key={candidate.id} onClick={() => setSelected(candidate)}><span className="avatar small-avatar">{candidate.alias.slice(4, 5)}</span><span>{candidate.alias}<small>{candidate.bio || "소개글 없음"}</small></span></button>)}</div> : <div className="selected-user"><span>{selected.alias}</span><button onClick={() => setReportUser(selected)}>신고</button><button onClick={() => { setSelected(null); setMessages([]); }}>변경 ×</button></div>}</div> : null}
          <div className="messages" aria-live="polite">{mode === "direct" && !selected ? <div className="chat-empty compact">대화할 사용자를 선택하세요.</div> : messages.length ? messages.map((message) => <div className={`message ${message.sender_id === user.id ? "mine" : ""}`} key={message.id}><span>{message.sender_alias}</span><p>{message.body}</p><time>{formatTime(message.created_at)}</time></div>) : <div className="chat-empty compact">첫 메시지를 남겨보세요.</div>}</div>
          <form className="message-form" onSubmit={send}><label htmlFor="message-input">메시지</label><input id="message-input" name="message" maxLength={500} autoComplete="off" placeholder="예의를 지켜 대화해 주세요" disabled={mode === "direct" && !selected} /><button aria-label="메시지 보내기" disabled={mode === "direct" && !selected}>↑</button></form>
          {reportUser ? <ReportDialog targetType="user" targetId={reportUser.id} label={reportUser.alias} onClose={() => setReportUser(null)} /> : null}
        </>
      )}
    </aside>
  );
}

function Profile({ user, sessionReady, onUserChange }: { user: User | null; sessionReady: boolean; onUserChange: (user: User) => void }) {
  const [tab, setTab] = useState<"account" | "products">("account");
  const [products, setProducts] = useState<Product[]>([]);
  const [passkeys, setPasskeys] = useState<PasskeySummary[]>([]);
  const [passkeyPending, setPasskeyPending] = useState(false);
  const [feedback, setFeedback] = useState("");
  const [editing, setEditing] = useState<Product | null>(null);
  useEffect(() => {
    if (tab === "products") api<{ products: Product[] }>("/api/products?mine=1").then((data) => setProducts(data.products)).catch((error) => setFeedback(errorMessage(error)));
  }, [tab]);
  useEffect(() => {
    if (user && tab === "account") {
      api<{ passkeys: PasskeySummary[] }>("/api/auth/passkeys")
        .then((data) => setPasskeys(data.passkeys))
        .catch((error) => setFeedback(errorMessage(error)));
    }
  }, [tab, user]);

  if (!sessionReady) return <PageLoading />;
  if (!user) return <SignInRequired />;

  async function updateAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setFeedback("");
    const form = new FormData(event.currentTarget);
    try {
      const data = await api<{ user: User }>("/api/profile", { method: "PATCH", body: JSON.stringify({ bio: form.get("bio"), currentPassword: form.get("currentPassword") || undefined, newPassword: form.get("newPassword") || undefined }) });
      onUserChange(data.user); setFeedback("계정 정보가 안전하게 저장되었습니다."); event.currentTarget.reset();
    } catch (error) { setFeedback(errorMessage(error)); }
  }

  async function removeProduct(id: string) {
    if (!window.confirm("상품을 삭제하면 다시 공개할 수 없습니다. 계속할까요?")) return;
    try { await api(`/api/products/${id}`, { method: "DELETE" }); setProducts((items) => items.filter((item) => item.id !== id)); } catch (error) { setFeedback(errorMessage(error)); }
  }

  async function registerPasskey() {
    const name = window.prompt("이 Passkey를 구분할 이름을 입력해 주세요.", "내 기기 Passkey");
    if (!name) return;
    setPasskeyPending(true); setFeedback("");
    try {
      const start = await api<{ challengeId: string; options: PublicKeyCredentialCreationOptionsJSON }>(
        "/api/auth/passkeys/registration/options",
        { method: "POST", body: "{}" },
      );
      const response = await startRegistration({ optionsJSON: start.options });
      await api("/api/auth/passkeys/registration/verify", {
        method: "POST",
        body: JSON.stringify({ challengeId: start.challengeId, response, name }),
      });
      const data = await api<{ passkeys: PasskeySummary[] }>("/api/auth/passkeys");
      setPasskeys(data.passkeys);
      setFeedback("Passkey가 등록되었습니다. 다음 로그인부터 비밀번호 없이 사용할 수 있습니다.");
    } catch (error) {
      setFeedback(ethereumProviderErrorMessage(error));
    } finally {
      setPasskeyPending(false);
    }
  }

  async function removePasskey(credentialId: string) {
    if (!window.confirm("이 Passkey를 삭제할까요? 다른 로그인 수단을 먼저 확인해 주세요.")) return;
    setPasskeyPending(true); setFeedback("");
    try {
      await api(`/api/auth/passkeys/${encodeURIComponent(credentialId)}`, { method: "DELETE" });
      setPasskeys((items) => items.filter((item) => item.id !== credentialId));
      setFeedback("Passkey를 삭제했습니다.");
    } catch (error) {
      setFeedback(errorMessage(error));
    } finally {
      setPasskeyPending(false);
    }
  }

  async function copyPublicAlias(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setFeedback("공개 hash 별칭을 복사했습니다.");
    } catch {
      setFeedback("별칭을 복사하지 못했습니다. 계정 설정의 전체 값을 직접 복사해 주세요.");
    }
  }

  return (
    <section className="profile-page">
      <div className="profile-rail"><div className="profile-identity"><div className="avatar large">{user.publicAlias.slice(4, 5).toUpperCase()}</div><p className="eyebrow"><span /> MY SAFER</p><div className="profile-alias-row"><h1 title={user.publicAlias}>{compactPublicAlias(user.publicAlias)}</h1><button type="button" onClick={() => void copyPublicAlias(user.publicAlias)} aria-label="공개 hash 별칭 전체 복사">복사</button></div><small className="profile-alias-caption">보안을 위해 생성된 공개 hash 별칭</small><p>{user.bio || "소개글을 등록해 신뢰를 더해보세요."}</p></div><nav><button className={tab === "account" ? "active" : ""} onClick={() => setTab("account")}>계정 설정 <span>→</span></button><button className={tab === "products" ? "active" : ""} onClick={() => setTab("products")}>내 상품 <span>→</span></button></nav><div className="security-card"><span>✓</span><div><b>계정 보호 활성화</b><small>세션과 요청이 서버에서 검증됩니다.</small></div></div></div>
      <div className="profile-content">
        {feedback ? <p className="inline-notice" role="status">{feedback}</p> : null}
        {tab === "account" ? <>
          <div className="content-heading"><p className="step-label">ACCOUNT</p><h2>계정 설정</h2><p>로그인 아이디는 본인에게만 표시되며, 외부에는 공개 별칭만 사용됩니다.</p></div>
          <form className="settings-form" onSubmit={updateAccount}>
            <label>로그인 아이디<input value={user.username} disabled /><small>비공개 인증 정보이며 다른 사용자에게 노출되지 않습니다.</small></label>
            <label>공개 별칭<input value={user.publicAlias} disabled /><small>상품과 채팅에서는 이 무작위 별칭만 표시됩니다.</small></label>
            <label>소개글<textarea name="bio" defaultValue={user.bio} maxLength={300} rows={4} /></label>
            <hr /><h3>기존 비밀번호 변경</h3>
            <div className="two-fields"><label>현재 비밀번호<input name="currentPassword" type="password" autoComplete="current-password" /></label><label>새 비밀번호<input name="newPassword" type="password" autoComplete="new-password" minLength={12} maxLength={128} /></label></div>
            <button className="button primary">변경사항 저장</button>
          </form>
          <section className="passkey-settings" aria-labelledby="passkey-settings-title">
            <div><p className="step-label">PASSKEYS</p><h3 id="passkey-settings-title">Passkey 관리</h3><p>기기 잠금·지문·얼굴 인식으로 로그인합니다. 개인키는 기기를 벗어나지 않고 서버에는 공개키만 저장됩니다.</p></div>
            <div className="passkey-actions"><span className="button ghost small" aria-label="Sites에서 ChatGPT 접근 신원 확인됨">ChatGPT 신원 확인됨</span><button className="button primary small" disabled={passkeyPending || !browserSupportsWebAuthn()} onClick={() => void registerPasskey()}>+ Passkey 등록</button></div>
            {passkeys.length ? <div className="passkey-list">{passkeys.map((passkey) => <article key={passkey.id}><div><strong>{passkey.name}</strong><small>{passkey.deviceType === "multiDevice" ? "동기화 가능한 Passkey" : "단일 기기 Passkey"} · {passkey.backedUp ? "백업됨" : "백업 미확인"}</small><small>등록 {formatTime(passkey.createdAt)}{passkey.lastUsedAt ? ` · 최근 사용 ${formatTime(passkey.lastUsedAt)}` : ""}</small></div><button className="button text-danger small" disabled={passkeyPending} onClick={() => void removePasskey(passkey.id)}>삭제</button></article>)}</div> : <p className="auth-method-note">등록된 Passkey가 없습니다. 계정 복구를 위해 서로 다른 기기에 2개 등록하는 것을 권장합니다.</p>}
          </section>
        </> : null}
        {tab === "products" ? <><div className="content-heading row"><div><p className="step-label">MY LISTINGS</p><h2>내 상품</h2></div><a className="button primary small" href="/products/new">+ 상품 등록</a></div>{products.length ? <div className="manage-list">{products.map((product) => <article key={product.id}><img src={product.imageUrl} alt="" /><div><span className={`status ${product.status}`}>{product.status}</span><h3>{product.name}</h3><strong>{money(product.price)}</strong></div><div><a className="button ghost small" href={`/products/${product.id}`}>보기</a>{product.status === "active" ? <button className="button ghost small" onClick={() => setEditing(product)}>편집</button> : null}{product.status !== "sold" ? <button className="button text-danger small" onClick={() => void removeProduct(product.id)}>삭제</button> : null}</div></article>)}</div> : <EmptyState title="등록한 상품이 없어요" body="사용하지 않는 물건을 안전하게 등록해 보세요." />}{editing ? <ProductEditDialog product={editing} onClose={() => setEditing(null)} onSaved={(updated) => { setProducts((items) => items.map((item) => item.id === updated.id ? updated : item)); setEditing(null); setFeedback("상품 정보가 수정되었습니다."); }} /> : null}</> : null}
      </div>
    </section>
  );
}

function WalletCenter({ user, sessionReady, onUserChange }: { user: User | null; sessionReady: boolean; onUserChange: (user: User) => void }) {
  const [wallet, setWallet] = useState<Wallet | null>(null);
  const [walletSeed, setWalletSeed] = useState("");
  const [walletPending, setWalletPending] = useState(false);
  const [web3Config, setWeb3Config] = useState<Web3Config | null>(null);
  const [web3Wallet, setWeb3Wallet] = useState<LinkedWeb3Wallet | null>(null);
  const [web3Pending, setWeb3Pending] = useState(false);
  const [transferPending, setTransferPending] = useState(false);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [productTrades, setProductTrades] = useState<ProductTrade[]>([]);
  const [productTradePending, setProductTradePending] = useState("");
  const [historyFilter, setHistoryFilter] = useState<"all" | "sent" | "received">("all");
  const [feedback, setFeedback] = useState("");
  const [transferError, setTransferError] = useState("");
  const transferRequestKey = useRef("");
  const productPaymentKeys = useRef<Record<string, string>>({});

  const loadWalletData = useCallback(async () => {
    const [walletData, transferData, productTradeData, chainConfig, linkedWallet] = await Promise.all([
      api<{ wallet: Wallet | null }>("/api/wallets/me"),
      api<{ transfers: Transfer[] }>("/api/transfers"),
      api<{ trades: ProductTrade[] }>("/api/product-trades"),
      api<Web3Config>("/api/web3/config"),
      api<{ wallet: LinkedWeb3Wallet | null }>("/api/web3/wallet"),
    ]);
    setWallet(walletData.wallet);
    setTransfers(transferData.transfers);
    setProductTrades(productTradeData.trades);
    setWeb3Config(chainConfig);
    setWeb3Wallet(linkedWallet.wallet);
  }, []);

  useEffect(() => {
    if (user) void loadWalletData().catch((error) => setFeedback(errorMessage(error)));
  }, [user, loadWalletData]);

  const transactionRows = transfers;
  const sentRows = transactionRows.filter((item) => item.direction === "sent");
  const receivedRows = transactionRows.filter((item) => item.direction === "received");
  const visibleRows = historyFilter === "all" ? transactionRows : historyFilter === "sent" ? sentRows : receivedRows;
  const sentTotal = sentRows.reduce((sum, item) => sum + item.amount, 0);
  const receivedTotal = receivedRows.reduce((sum, item) => sum + item.amount, 0);

  if (!sessionReady) return <PageLoading />;
  if (!user) return <SignInRequired />;

  async function transfer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setFeedback(""); setTransferError("");
    if (transferPending) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const recipientWalletId = String(form.get("walletId") ?? "").trim();
    if (!/^wlt_[A-Za-z0-9_-]{43}$/.test(recipientWalletId)) {
      setTransferError("입금 주소는 wlt_로 시작하는 47자 hash ID만 입력할 수 있습니다. 사용자 아이디는 사용할 수 없습니다.");
      return;
    }
    if (wallet && recipientWalletId === wallet.id) {
      setTransferError("송금 주소와 입금 주소가 동일합니다. 본인 지갑으로 송금할 수 없습니다.");
      return;
    }
    const idempotencyKey = transferRequestKey.current || crypto.randomUUID();
    transferRequestKey.current = idempotencyKey;
    setTransferPending(true);
    try {
      await api("/api/transfers", { method: "POST", headers: { "idempotency-key": idempotencyKey }, body: JSON.stringify({ walletId: recipientWalletId, amount: form.get("amount"), memo: form.get("memo") }) });
      transferRequestKey.current = "";
      formElement.reset();
      const [session] = await Promise.all([api<{ user: User }>("/api/auth/me"), loadWalletData()]);
      if (session.user) onUserChange(session.user);
      setFeedback("송금이 완료되었습니다. 거래 데이터가 갱신되었습니다.");
    } catch (error) { setTransferError(errorMessage(error)); }
    finally { setTransferPending(false); }
  }

  function resetTransferAttempt() {
    transferRequestKey.current = "";
    setTransferError("");
  }

  async function registerWallet() {
    setFeedback(""); setWalletPending(true);
    try {
      const data = await api<{ wallet: Wallet; seed: string; accountActivated: boolean }>("/api/wallets", { method: "POST" });
      setWallet(data.wallet); setWalletSeed(data.seed);
      const session = await api<{ user: User }>("/api/auth/me");
      if (session.user) onUserChange(session.user);
      setFeedback(data.accountActivated ? "지갑 계정이 활성화되었습니다. 잔액은 0원에서 시작합니다." : "지갑이 등록되었습니다. seed를 보관한 뒤 Ethereum 지갑 연결을 완료해 주세요.");
    } catch (error) { setFeedback(errorMessage(error)); }
    finally { setWalletPending(false); }
  }

  async function linkEthereumWallet() {
    setFeedback(""); setWeb3Pending(true);
    try {
      if (!wallet) throw new Error("먼저 개인 거래 지갑을 등록해 주세요.");
      const provider = window.ethereum;
      if (!provider) throw new Error("Ethereum 지갑 확장 프로그램을 찾지 못했습니다. 신뢰할 수 있는 지갑을 설치한 뒤 다시 시도해 주세요.");
      if (!web3Config) throw new Error("Ethereum 네트워크 설정을 불러오지 못했습니다.");
      const accountResult = await provider.request({ method: "eth_requestAccounts" });
      if (!Array.isArray(accountResult) || typeof accountResult[0] !== "string") throw new Error("지갑 계정을 선택하지 않았습니다.");
      const address = accountResult[0];
      const currentChain = await provider.request({ method: "eth_chainId" });
      const expectedChain = `0x${web3Config.chainId.toString(16)}`;
      if (typeof currentChain !== "string" || currentChain.toLowerCase() !== expectedChain) {
        try {
          await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: expectedChain }] });
        } catch {
          throw new Error(`${web3Config.chainName} 네트워크로 전환한 뒤 다시 시도해 주세요.`);
        }
      }
      const challenge = await api<{ challengeToken: string; message: string; address: string }>("/api/web3/challenge", {
        method: "POST",
        body: JSON.stringify({ address }),
      });
      const signature = await provider.request({ method: "personal_sign", params: [challenge.message, challenge.address] });
      if (typeof signature !== "string") throw new Error("지갑 서명을 받지 못했습니다.");
      const result = await api<{ wallet: LinkedWeb3Wallet; accountActivated: boolean }>("/api/web3/link", {
        method: "POST",
        body: JSON.stringify({ address: challenge.address, challengeToken: challenge.challengeToken, message: challenge.message, signature }),
      });
      setWeb3Wallet(result.wallet);
      const session = await api<{ user: User }>("/api/auth/me");
      if (session.user) onUserChange(session.user);
      setFeedback(result.accountActivated ? "계정 연결이 완료되었습니다. 잔액은 0원에서 시작합니다." : "Ethereum 지갑 소유권 확인이 완료되었습니다. 개인키와 seed는 서버로 전송되지 않았습니다.");
    } catch (error) {
      setFeedback(errorMessage(error));
    } finally {
      setWeb3Pending(false);
    }
  }

  async function changeProductTrade(trade: ProductTrade, action: "accept" | "cancel") {
    setFeedback(""); setProductTradePending(trade.id);
    try {
      await api(`/api/product-trades/${trade.id}`, { method: "PATCH", body: JSON.stringify({ action }) });
      await loadWalletData();
      setFeedback(action === "accept" ? "구매 요청을 승인했습니다. 구매자의 결제를 기다립니다." : "상품 거래를 취소했습니다.");
    } catch (error) { setFeedback(errorMessage(error)); }
    finally { setProductTradePending(""); }
  }

  async function payForProduct(trade: ProductTrade) {
    if (productTradePending) return;
    const idempotencyKey = productPaymentKeys.current[trade.id] || crypto.randomUUID();
    productPaymentKeys.current[trade.id] = idempotencyKey;
    setFeedback(""); setProductTradePending(trade.id);
    try {
      await api(`/api/product-trades/${trade.id}/pay`, { method: "POST", headers: { "idempotency-key": idempotencyKey } });
      delete productPaymentKeys.current[trade.id];
      const [session] = await Promise.all([api<{ user: User }>("/api/auth/me"), loadWalletData()]);
      if (session.user) onUserChange(session.user);
      setFeedback("상품 결제가 완료되어 송금·수금 데이터와 상품 거래가 함께 갱신되었습니다.");
    } catch (error) { setFeedback(errorMessage(error)); }
    finally { setProductTradePending(""); }
  }

  async function copyValue(value: string, label: string) {
    try { await navigator.clipboard.writeText(value); setFeedback(`${label}을 클립보드에 복사했습니다.`); }
    catch { setFeedback(`${label} 복사에 실패했습니다. 직접 선택해 복사해 주세요.`); }
  }

  return (
    <section className="wallet-page">
      <header className="wallet-page-header">
        <div>
          <p className="eyebrow"><span /> WALLET & TRANSACTIONS</p>
          <h1>지갑과 거래</h1>
          <p>송금과 수금 흐름을 분리해 확인하고, 모든 거래 데이터를 한곳에서 관리하세요.</p>
        </div>
        <div className="wallet-balance-card">
          <span>사용 가능 잔액</span>
          <strong>{user.walletReady && user.balance !== null ? money(user.balance) : "활성화 대기"}</strong>
          <small>{user.walletReady ? "모든 잔액 변경은 D1 트리거로 원자적으로 처리됩니다." : "거래 지갑 등록과 Ethereum 계정 연결 후 잔액 표시가 활성화되며 0원에서 시작합니다."}</small>
        </div>
      </header>

      {feedback ? <p className="inline-notice wallet-notice" role="status">{feedback}</p> : null}

      <section className="web3-identity" aria-labelledby="web3-identity-title">
        <div className="web3-network-mark" aria-hidden="true">Ξ</div>
        <div className="web3-copy">
          <p className="step-label">ETHEREUM IDENTITY</p>
          <h2 id="web3-identity-title">외부 Ethereum 지갑</h2>
          <p>SIWE 형식의 5분 제한 일회용 메시지에 서명해 계정 소유권만 증명합니다. 개인키·복구문구·송금 권한은 요청하지 않습니다.</p>
          <div className="web3-status-row">
            <span>{web3Config?.chainName ?? "네트워크 확인 중"}</span>
            <span className={web3Config?.settlementEnabled ? "ready" : "pending"}>{web3Config?.settlementEnabled ? "에스크로 활성" : "에스크로 배포 대기"}</span>
          </div>
          {web3Wallet ? <div className="web3-address"><code>{web3Wallet.address}</code><small>{web3Wallet.accountKind === "contract" ? "스마트 계정" : "EOA"} · {formatDate(web3Wallet.verifiedAt)} 검증</small></div> : null}
        </div>
        <button className="button primary" disabled={web3Pending || !wallet || !web3Config?.walletLinkEnabled} onClick={() => void linkEthereumWallet()}>{web3Pending ? "서명 확인 중…" : !wallet ? "거래 지갑 등록 후 연결" : web3Wallet ? "다른 지갑으로 재검증" : "Ethereum 지갑 연결"}</button>
      </section>

      {walletSeed ? <aside className="seed-reveal wallet-seed" role="alert"><strong>복구 seed · 이번에만 표시됩니다</strong><code>{walletSeed}</code><p>DB에는 저장되지 않습니다. 화면을 닫기 전에 오프라인 보관소에 복사하세요.</p><div><button className="button ghost small" onClick={() => void copyValue(walletSeed, "지갑 seed")}>seed 복사</button><button className="button text-danger small" onClick={() => setWalletSeed("")}>확인하고 숨기기</button></div></aside> : null}

      {!wallet ? (
        <section className="wallet-onboarding">
          <div className="wallet-onboarding-mark" aria-hidden="true">◇</div>
          <div><p className="step-label">CREATE WALLET</p><h2>거래 지갑을 먼저 등록하세요</h2><p>서버가 256비트 seed를 만들고 공개 SHA-256 hash ID만 저장합니다.</p></div>
          <button className="button primary" disabled={walletPending} onClick={() => void registerWallet()}>{walletPending ? "지갑 생성 중…" : "개인 지갑 등록하기"}</button>
        </section>
      ) : !user.walletReady ? (
        <section className="wallet-onboarding">
          <div className="wallet-onboarding-mark" aria-hidden="true">Ξ</div>
          <div><p className="step-label">CONNECT ACCOUNT</p><h2>Ethereum 계정 연결이 필요합니다</h2><p>위의 연결 버튼으로 지갑 소유권을 확인하면 계정과 잔액 표시가 활성화되며 0원에서 시작합니다.</p></div>
          <button className="button primary" disabled={web3Pending} onClick={() => void linkEthereumWallet()}>{web3Pending ? "서명 확인 중…" : "Ethereum 지갑 연결"}</button>
        </section>
      ) : (
        <>
          <div className="wallet-flow-panels">
            <article className="wallet-action-panel send-action-panel">
              <div className="wallet-panel-heading"><span className="flow-icon sent" aria-hidden="true">↑</span><div><p className="step-label">SEND</p><h2>송금</h2><p>상대방의 공개 hash ID로 금액을 보냅니다.</p></div></div>
              <div className="flow-visual sent-flow" aria-label="내 지갑에서 상대 지갑으로 송금"><span>내 지갑</span><i>→</i><span>상대 hash ID</span></div>
              <form className="wallet-transfer-form" onSubmit={transfer}>
                <label>입금 지갑 hash ID<input name="walletId" type="text" minLength={47} maxLength={47} pattern="wlt_[A-Za-z0-9_-]{43}" required autoComplete="off" spellCheck={false} placeholder="wlt_로 시작하는 47자 주소" onChange={resetTransferAttempt} disabled={transferPending} /><small>사용자 아이디가 아닌 공개 지갑 주소만 입력할 수 있습니다.</small></label>
                {transferError ? <p className="inline-error" role="alert">{transferError}</p> : null}
                <div className="wallet-form-row"><label>금액<input name="amount" inputMode="numeric" pattern="[0-9]+" min={1} max={100_000_000} required placeholder="0" onChange={resetTransferAttempt} disabled={transferPending} /></label><label>메모<input name="memo" maxLength={100} placeholder="선택 사항" onChange={resetTransferAttempt} disabled={transferPending} /></label></div>
                <button className="button primary wide" disabled={transferPending} aria-busy={transferPending}>{transferPending ? "송금 처리 중…" : "안전하게 송금하기"}</button>
              </form>
              <dl className="panel-metrics"><div><dt>누적 송금</dt><dd>{money(sentTotal)}</dd></div><div><dt>송금 건수</dt><dd>{sentRows.length}건</dd></div></dl>
            </article>

            <article className="wallet-action-panel receive-action-panel">
              <div className="wallet-panel-heading"><span className="flow-icon received" aria-hidden="true">↓</span><div><p className="step-label">RECEIVE</p><h2>수금</h2><p>내 공개 주소를 공유해 안전하게 금액을 받습니다.</p></div></div>
              <div className="flow-visual receive-flow" aria-label="상대 지갑에서 내 지갑으로 수금"><span>상대 지갑</span><i>→</i><span>내 hash ID</span></div>
              <div className="receive-address-card">
                <span>나의 입금 주소</span>
                <code>{wallet.id}</code>
                <button className="button ghost small" onClick={() => void copyValue(wallet.id, "입금 주소")}>주소 복사</button>
                <small>seed는 공유하지 마세요. 입금에는 이 공개 hash ID만 사용합니다.</small>
              </div>
              <dl className="panel-metrics"><div><dt>누적 수금</dt><dd>{money(receivedTotal)}</dd></div><div><dt>수금 건수</dt><dd>{receivedRows.length}건</dd></div></dl>
              <div className="latest-receipt"><span>최근 수금</span>{receivedRows[0] ? <><strong>+{money(receivedRows[0].amount)}</strong><small>{receivedRows[0].peer_alias ?? (receivedRows[0].peer_wallet_id ? shortWalletId(receivedRows[0].peer_wallet_id) : "비공개 거래 상대")} · {formatDate(receivedRows[0].created_at)}</small></> : <p>아직 수금 내역이 없습니다.</p>}</div>
            </article>
          </div>

          <section className="product-trade-ledger" aria-labelledby="product-trade-ledger-title">
            <header><div><p className="step-label">MARKETPLACE TRADES</p><h2 id="product-trade-ledger-title">상품 거래</h2><p>구매 요청부터 승인, 결제, 판매 대금 수금까지 상품과 연결해 확인합니다.</p></div><a className="button ghost small" href="/market">상품 둘러보기</a></header>
            {productTrades.length ? <div className="product-trade-list">{productTrades.map((trade) => <article key={trade.id}>
              <a className="product-trade-image" href={`/products/${trade.productId}`}><img src={trade.productImageUrl} alt="" /></a>
              <div className="product-trade-copy"><div><span className={`status trade-${trade.status}`}>{tradeStatusLabel(trade.status)}</span><span className="trade-role">{trade.role === "buyer" ? "구매" : "판매"}</span></div><h3><a href={`/products/${trade.productId}`}>{trade.productName}</a></h3><p>거래 상대 {trade.counterpartyAlias} · {formatDate(trade.updatedAt)}</p></div>
              <strong>{money(trade.price)}</strong>
              <div className="product-trade-actions">
                {trade.status === "requested" && trade.role === "seller" ? <><button className="button primary small" disabled={productTradePending === trade.id} onClick={() => void changeProductTrade(trade, "accept")}>승인</button><button className="button ghost small" disabled={productTradePending === trade.id} onClick={() => void changeProductTrade(trade, "cancel")}>거절</button></> : null}
                {trade.status === "requested" && trade.role === "buyer" ? <button className="button text-danger small" disabled={productTradePending === trade.id} onClick={() => void changeProductTrade(trade, "cancel")}>요청 취소</button> : null}
                {trade.status === "accepted" && trade.role === "buyer" ? <><button className="button primary small" disabled={productTradePending === trade.id} onClick={() => void payForProduct(trade)}>{productTradePending === trade.id ? "결제 중…" : "결제"}</button><button className="button ghost small" disabled={productTradePending === trade.id} onClick={() => void changeProductTrade(trade, "cancel")}>취소</button></> : null}
                {trade.status === "accepted" && trade.role === "seller" ? <><span className="trade-waiting">구매자 결제 대기</span><button className="button text-danger small" disabled={productTradePending === trade.id} onClick={() => void changeProductTrade(trade, "cancel")}>취소</button></> : null}
                {trade.status === "completed" ? <a className="button ghost small" href={`/products/${trade.productId}`}>완료 내역</a> : null}
                {trade.status === "cancelled" ? <span className="trade-waiting">종료된 요청</span> : null}
              </div>
            </article>)}</div> : <div className="transaction-empty"><span>◇</span><p>아직 상품과 연결된 거래가 없습니다.</p></div>}
          </section>

          <section className="transaction-data" aria-labelledby="transaction-data-title">
            <header><div><p className="step-label">TRANSACTION DATA</p><h2 id="transaction-data-title">거래 데이터</h2><p>송금과 수금 내역을 방향별로 분리해 확인할 수 있습니다.</p></div><dl><div><dt>전체</dt><dd>{transactionRows.length}건</dd></div><div><dt>송금</dt><dd>{money(sentTotal)}</dd></div><div><dt>수금</dt><dd>{money(receivedTotal)}</dd></div></dl></header>
            <div className="transaction-tabs" role="tablist" aria-label="거래 데이터 필터">
              <button role="tab" aria-selected={historyFilter === "all"} className={historyFilter === "all" ? "active" : ""} onClick={() => setHistoryFilter("all")}>전체 거래 <span>{transactionRows.length}</span></button>
              <button role="tab" aria-selected={historyFilter === "sent"} className={historyFilter === "sent" ? "active" : ""} onClick={() => setHistoryFilter("sent")}>송금 <span>{sentRows.length}</span></button>
              <button role="tab" aria-selected={historyFilter === "received"} className={historyFilter === "received" ? "active" : ""} onClick={() => setHistoryFilter("received")}>수금 <span>{receivedRows.length}</span></button>
            </div>
            <div className="transaction-list" role="tabpanel">
              {visibleRows.length ? visibleRows.map((item) => <article key={item.id}><span className={`transaction-direction ${item.direction}`}>{item.direction === "sent" ? "↑" : "↓"}</span><div><b>{item.direction === "sent" ? "송금" : "수금"}{item.product_trade_id ? <em className="linked-trade">상품 거래</em> : null}</b><code>{item.product_trade_id ? item.peer_alias ?? "거래 상대 비공개" : item.peer_wallet_id ? shortWalletId(item.peer_wallet_id) : "비공개 지갑"}</code><small>{item.memo || "메모 없음"} · {formatDate(item.created_at)}</small></div><strong className={item.direction}>{item.direction === "sent" ? "−" : "+"}{money(item.amount)}</strong></article>) : <div className="transaction-empty"><span>◇</span><p>선택한 유형의 거래 데이터가 없습니다.</p></div>}
            </div>
          </section>
        </>
      )}
    </section>
  );
}

function AdminFrame({ user, onLogout, children }: { user: User; onLogout: () => void; children: React.ReactNode }) {
  return (
    <div className="admin-console-shell">
      <header className="admin-console-topbar">
        <a className="brand light" href="/admin" aria-label="SAFER 관리자 대시보드">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>SAFER<small>admin operations</small></span>
        </a>
        <nav aria-label="관리자 메뉴">
          <a className="active" href="/admin">운영 대시보드</a>
          <a href="/market">사용자 화면</a>
        </nav>
        <div className="admin-console-account">
          <span><b>ADMIN</b>{compactPublicAlias(user.publicAlias)}</span>
          <button className="button admin-logout small" onClick={onLogout}>관리자 로그아웃</button>
        </div>
      </header>
      {children}
    </div>
  );
}

function Admin({ user, sessionReady, onLogout }: { user: User | null; sessionReady: boolean; onLogout: () => void }) {
  const [data, setData] = useState<AdminData | null>(null);
  const [tab, setTab] = useState<"users" | "products" | "reports" | "transfers" | "messages" | "logs">("users");
  const [error, setError] = useState("");
  const load = useCallback(() => api<AdminData>("/api/admin/summary").then(setData).catch((caught) => setError(errorMessage(caught))), []);
  useEffect(() => { if (user?.role === "admin") void load(); }, [user, load]);
  if (!sessionReady) return <PageLoading />;
  if (!user || user.role !== "admin") return <div className="admin-access-gate"><a className="brand" href="/"><span className="brand-mark">S</span><span>SAFER<small>secure secondhand</small></span></a><EmptyState title="관리자 콘솔에 접근할 수 없어요" body="관리자 권한으로 로그인한 계정만 사용할 수 있습니다." action={<a className="button primary" href="/login">관리자 로그인</a>} /></div>;
  if (error) return <AdminFrame user={user} onLogout={onLogout}><EmptyState title="관리 데이터를 불러오지 못했어요" body={error} /></AdminFrame>;
  if (!data) return <AdminFrame user={user} onLogout={onLogout}><PageLoading /></AdminFrame>;
  const alertCount = data.securityAlerts.reduce((sum, item) => sum + Number(item.count), 0);

  async function change(endpoint: string, status: string) { try { await api(endpoint, { method: "PATCH", body: JSON.stringify({ status }) }); await load(); } catch (caught) { setError(errorMessage(caught)); } }
  async function removeMessage(id: string) { if (!window.confirm("부적절한 메시지를 삭제할까요?")) return; try { await api(`/api/admin/messages/${id}`, { method: "DELETE" }); await load(); } catch (caught) { setError(errorMessage(caught)); } }
  const tabHeading = {
    users: ["사용자 관리", "계정 상태와 관리자 권한을 확인합니다."],
    products: ["상품 관리", "등록 상품의 공개·차단·삭제 상태를 통제합니다."],
    reports: ["신고 검토", "사용자 신고의 사유를 검토하고 처리합니다."],
    transfers: ["거래 모니터링", "플랫폼 송금 흐름과 금액을 감사합니다."],
    messages: ["메시지 관리", "신고된 커뮤니케이션을 확인하고 조치합니다."],
    logs: ["감사 로그", "관리 및 보안 이벤트의 변경 이력을 추적합니다."],
  }[tab];
  return (
    <AdminFrame user={user} onLogout={onLogout}>
      <section className="admin-page">
      <header className="admin-hero"><div><p className="eyebrow light"><span /> ADMIN CONSOLE</p><h1>관리자 대시보드</h1><p>사용자, 상품, 신고와 보안 이벤트를 권한이 검증된 운영자만 관리합니다.</p></div><div className="admin-operator"><span className="admin-operator-mark" aria-hidden="true">A</span><div><small>현재 운영자</small><strong>{compactPublicAlias(user.publicAlias)}</strong><span>권한 · ADMINISTRATOR</span></div></div></header>
      <div className="admin-kpis"><div><span>전체 사용자</span><strong>{data.users.length}</strong></div><div><span>등록 상품</span><strong>{data.products.length}</strong></div><div><span>미처리 신고</span><strong>{data.reports.filter((item) => item.status === "open").length}</strong></div><div><span>24시간 보안 경보</span><strong>{alertCount}</strong></div></div>
      <div className="admin-dashboard-grid">
        <aside className="admin-sidebar" aria-label="관리자 기능">
          <div><span className="admin-sidebar-mark">S</span><p><strong>SAFER OPS</strong><small>secure control plane</small></p></div>
          <nav className="admin-tabs">
            <button className={tab === "users" ? "active" : ""} onClick={() => setTab("users")}><span>01</span>사용자</button>
            <button className={tab === "products" ? "active" : ""} onClick={() => setTab("products")}><span>02</span>상품</button>
            <button className={tab === "reports" ? "active" : ""} onClick={() => setTab("reports")}><span>03</span>신고</button>
            <button className={tab === "transfers" ? "active" : ""} onClick={() => setTab("transfers")}><span>04</span>거래</button>
            <button className={tab === "messages" ? "active" : ""} onClick={() => setTab("messages")}><span>05</span>메시지</button>
            <button className={tab === "logs" ? "active" : ""} onClick={() => setTab("logs")}><span>06</span>감사 로그</button>
          </nav>
          <a href="/market">← 사용자 화면으로</a>
        </aside>
        <div className="admin-workspace">
          <header className="admin-workspace-heading"><div><p className="step-label">OPERATIONS</p><h2>{tabHeading[0]}</h2><p>{tabHeading[1]}</p></div><span className="admin-live"><i /> LIVE</span></header>
          {data.securityAlerts.length ? <aside className="security-alerts" role="status"><strong>최근 24시간 보안 이벤트</strong><div>{data.securityAlerts.map((item) => <span key={item.action}><code>{item.action}</code><b>{item.count}건</b><small>{formatDate(item.last_seen_at)}</small></span>)}</div></aside> : null}
          <div className="admin-table-wrap">{tab === "users" ? <table><thead><tr><th>아이디</th><th>권한</th><th>상태</th><th>잔액</th><th>관리</th></tr></thead><tbody>{data.users.map((item) => <tr key={item.id}><td><b>@{item.username}</b><small>{item.bio || "소개글 없음"}</small></td><td>{item.role}</td><td><span className={`status ${item.status}`}>{item.status}</span></td><td>{money(item.balance)}</td><td>{item.role !== "admin" ? <button className="button ghost small" onClick={() => void change(`/api/admin/users/${item.id}`, item.status === "active" ? "dormant" : "active")}>{item.status === "active" ? "휴면 전환" : "복구"}</button> : "—"}</td></tr>)}</tbody></table> : null}
      {tab === "products" ? <table><thead><tr><th>상품</th><th>판매자</th><th>가격</th><th>상태</th><th>관리</th></tr></thead><tbody>{data.products.map((item) => <tr key={item.id}><td><b>{item.name}</b><small>{formatDate(item.created_at)}</small></td><td>@{item.seller_username}</td><td>{money(item.price)}</td><td><span className={`status ${item.status}`}>{item.status}</span></td><td><select aria-label={`${item.name} 상태`} value={item.status} disabled={item.status === "sold"} onChange={(event) => void change(`/api/admin/products/${item.id}`, event.target.value)}><option value="active">active</option><option value="blocked">blocked</option><option value="deleted">deleted</option>{item.status === "sold" ? <option value="sold">sold</option> : null}</select></td></tr>)}</tbody></table> : null}
      {tab === "reports" ? <table><thead><tr><th>신고자</th><th>대상</th><th>사유</th><th>상태</th><th>관리</th></tr></thead><tbody>{data.reports.map((item) => <tr key={item.id}><td>@{item.reporter_username}</td><td>{item.target_type}<small>{item.target_id}</small></td><td className="reason-cell">{item.reason}</td><td><span className={`status ${item.status}`}>{item.status}</span></td><td>{item.status === "open" ? <><button className="button ghost small" onClick={() => void change(`/api/admin/reports/${item.id}`, "reviewed")}>처리</button><button className="button text-danger small" onClick={() => void change(`/api/admin/reports/${item.id}`, "dismissed")}>기각</button></> : "—"}</td></tr>)}</tbody></table> : null}
      {tab === "transfers" ? <table><thead><tr><th>시각</th><th>보낸 지갑</th><th>받는 지갑</th><th>금액</th><th>메모</th></tr></thead><tbody>{data.transfers.map((item) => <tr key={item.id}><td>{formatDate(item.created_at)}</td><td>@{item.sender_username}<small>{item.sender_wallet_id ? shortWalletId(item.sender_wallet_id) : "이전 방식 기록"}</small></td><td>@{item.recipient_username}<small>{item.recipient_wallet_id ? shortWalletId(item.recipient_wallet_id) : "이전 방식 기록"}</small></td><td><b>{money(item.amount)}</b></td><td>{item.memo || "—"}</td></tr>)}</tbody></table> : null}
      {tab === "messages" ? <table><thead><tr><th>시각</th><th>발신자</th><th>채널</th><th>메시지</th><th>관리</th></tr></thead><tbody>{data.messages.map((item) => <tr key={item.id}><td>{formatDate(item.created_at)}</td><td>@{item.sender_username}</td><td>{item.recipient_username ? `1:1 → @${item.recipient_username}` : "전체"}</td><td className="reason-cell">{item.body}</td><td><button className="button text-danger small" onClick={() => void removeMessage(item.id)}>삭제</button></td></tr>)}</tbody></table> : null}
          {tab === "logs" ? <table><thead><tr><th>시각</th><th>행위</th><th>대상</th><th>행위자</th></tr></thead><tbody>{data.logs.map((item) => <tr key={item.id}><td>{formatDate(item.created_at)}</td><td><code>{item.action}</code></td><td>{item.target_type}<small>{item.target_id || "—"}</small></td><td>{item.actor_id || "system"}</td></tr>)}</tbody></table> : null}</div>
        </div>
      </div>
      </section>
    </AdminFrame>
  );
}

function ReportDialog({ targetType, targetId, label, onClose }: { targetType: "user" | "product"; targetId: string; label: string; onClose: () => void }) {
  const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const form = new FormData(event.currentTarget); try { await api("/api/reports", { method: "POST", body: JSON.stringify({ targetType, targetId, reason: form.get("reason") }) }); window.alert("신고가 접수되었습니다. 관리자가 확인합니다."); onClose(); } catch (caught) { setError(errorMessage(caught)); } }
  return <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) onClose(); }}><div className="dialog" role="dialog" aria-modal="true" aria-labelledby="report-title"><button className="dialog-close" onClick={onClose} aria-label="신고 창 닫기">×</button><p className="step-label">REPORT</p><h2 id="report-title">{label} 신고</h2><p>구체적인 사유를 작성해 주세요. 같은 대상을 중복 신고할 수 없습니다.</p><form onSubmit={submit}><label>신고 사유<textarea name="reason" minLength={10} maxLength={500} rows={5} required autoFocus /></label>{error ? <p className="form-error" role="alert">{error}</p> : null}<button className="button danger wide">신고 접수</button></form></div></div>;
}

function ProductEditDialog({ product, onClose, onSaved }: { product: Product; onClose: () => void; onSaved: (product: Product) => void }) {
  const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const updated = { ...product, name: String(form.get("name")), price: Number(form.get("price")), description: String(form.get("description")) };
    try {
      await api(`/api/products/${product.id}`, { method: "PATCH", body: JSON.stringify(updated) });
      onSaved(updated);
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }
  return <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) onClose(); }}><div className="dialog" role="dialog" aria-modal="true" aria-labelledby="edit-title"><button className="dialog-close" onClick={onClose} aria-label="편집 창 닫기">×</button><p className="step-label">EDIT LISTING</p><h2 id="edit-title">상품 정보 편집</h2><form onSubmit={submit}><label>상품명<input name="name" defaultValue={product.name} minLength={2} maxLength={80} required /></label><label>가격<input name="price" defaultValue={product.price} inputMode="numeric" pattern="[0-9]+" min={1} max={1_000_000_000} required /></label><label>상품 설명<textarea name="description" defaultValue={product.description} minLength={10} maxLength={3000} rows={5} required /></label>{error ? <p className="form-error" role="alert">{error}</p> : null}<button className="button primary wide">수정 저장</button></form></div></div>;
}

function LoadingCards() { return <div className="product-grid">{[1, 2, 3, 4].map((key) => <div className="product-card skeleton" key={key}><div /><p /><p /></div>)}</div>; }
function PageLoading() { return <div className="page-loading" role="status"><span /><p>안전하게 불러오는 중…</p></div>; }
function SignInRequired() { return <EmptyState title="로그인이 필요해요" body="이 기능은 로그인한 사용자만 사용할 수 있습니다." action={<a className="button primary" href="/login">로그인</a>} />; }
function EmptyState({ title, body, action }: { title: string; body: string; action?: React.ReactNode }) { return <div className="empty-state"><span>◇</span><h2>{title}</h2><p>{body}</p>{action}</div>; }

function PrivacyPolicy() {
  return (
    <article className="privacy-page">
      <header className="privacy-hero">
        <p className="eyebrow"><span /> PRIVACY AT SAFER</p>
        <h1>개인정보처리방침</h1>
        <p>SAFER는 서비스 제공에 필요한 정보만 처리하고, 계정·거래·지갑 정보를 서로 분리하여 보호합니다.</p>
        <div className="privacy-summary" aria-label="개인정보 처리 핵심 요약">
          <span><b>최소 수집</b>서비스에 필요한 항목만</span>
          <span><b>원문 미저장</b>연합 신원은 HMAC 가명화</span>
          <span><b>광고 추적 없음</b>행태정보 광고에 미사용</span>
          <span><b>권리 보장</b>열람·정정·삭제 요청 가능</span>
        </div>
      </header>

      <div className="privacy-layout">
        <aside className="privacy-index" aria-label="개인정보처리방침 목차">
          <strong>목차</strong>
          <a href="#privacy-purpose">1. 처리 목적과 항목</a>
          <a href="#privacy-retention">2. 보유 및 이용기간</a>
          <a href="#privacy-sharing">3. 제공·위탁·국외 이전</a>
          <a href="#privacy-destruction">4. 파기 절차와 방법</a>
          <a href="#privacy-rights">5. 정보주체의 권리</a>
          <a href="#privacy-security">6. 안전성 확보조치</a>
          <a href="#privacy-cookies">7. 쿠키와 자동화 조치</a>
          <a href="#privacy-contact">8. 문의 및 변경</a>
        </aside>

        <div className="privacy-content">
          <section className="privacy-notice" aria-label="정책 적용 안내">
            <strong>교육·검증용 서비스 안내</strong>
            <p>본 방침은 2026년 7월 26일 현재 SAFER 코드와 배포 구성을 기준으로 작성되었습니다. 정식 상용 운영 전에는 실제 사업자 정보, 개인정보 보호책임자 연락처, 법정 보유기간 및 국외 이전·위탁 계약을 최종 확정해야 합니다.</p>
          </section>

          <section id="privacy-purpose">
            <span className="privacy-number">01</span>
            <h2>개인정보의 처리 목적과 항목</h2>
            <p>SAFER는 회원 식별, 안전한 거래, 커뮤니티 운영과 보안 사고 대응을 위해 아래 정보를 처리합니다.</p>
            <div className="privacy-table-wrap">
              <table>
                <thead><tr><th>구분</th><th>처리 항목</th><th>목적</th></tr></thead>
                <tbody>
                  <tr><td>회원·인증</td><td>로그인 ID, 비밀번호 해시, 공개 별칭, 선택 소개글, 역할·상태, 가입·수정 시각, ChatGPT 연합 신원 HMAC 해시</td><td>가입, 로그인, 계정 관리, 중복 가입 방지</td></tr>
                  <tr><td>세션·Passkey</td><td>세션·CSRF 토큰의 해시, 만료·최근 이용 시각, Passkey credential ID·공개키·서명 카운터·기기 유형·백업 여부</td><td>로그인 유지, 재사용 방지, 피싱 저항형 인증</td></tr>
                  <tr><td>상품·커뮤니티</td><td>상품명·설명·가격·이미지, 채팅 메시지, 신고 대상·사유·처리 상태</td><td>상품 게시, 사용자 소통, 신고 처리와 안전 조치</td></tr>
                  <tr><td>거래·지갑</td><td>내부 hash 지갑 ID, 송·수신자 내부 ID, 금액·메모·거래 시각·상태, 상품 거래별 별칭, Ethereum 공개 주소·체인 ID·검증 시각</td><td>송금, 상품 결제, 중복·자가 거래 방지, 지갑 소유권 확인</td></tr>
                  <tr><td>보안·접속</td><td>IP 기반 일방향 해시·요청 제한 키, 요청 ID, 오류 종류, 보안 이벤트, 감사 로그</td><td>자동화 요청 방어, 부정 이용 탐지, 장애·보안 사고 조사</td></tr>
                </tbody>
              </table>
            </div>
            <p className="privacy-detail">Sites가 전달하는 인증 이메일은 연합 신원을 가명화하는 과정에서만 사용하며 원문을 회원 DB에 저장하지 않습니다. SAFER는 Passkey 개인키·생체정보, ChatGPT 토큰, Ethereum 개인키·복구문구를 수집하지 않습니다. 내부 지갑 seed는 생성 시 한 번만 제공하고 서버에 저장하지 않습니다.</p>
          </section>

          <section id="privacy-retention">
            <span className="privacy-number">02</span>
            <h2>개인정보의 보유 및 이용기간</h2>
            <ul>
              <li><b>회원·프로필·Passkey·연결 지갑:</b> 회원 탈퇴 또는 삭제 요청 처리 시까지</li>
              <li><b>로그인 세션:</b> 발급 후 최대 8시간, 30분 동안 활동이 없으면 조기 만료</li>
              <li><b>Passkey·Ethereum 서명 challenge:</b> 발급 후 5분 또는 일회 사용 시까지</li>
              <li><b>요청 제한 키:</b> 마지막 제한 구간 후 최대 2일</li>
              <li><b>상품·채팅·신고·거래·감사 기록:</b> 서비스 운영과 거래 무결성, 분쟁·보안 사고 대응에 필요한 기간 또는 삭제 요청 처리 시까지. 관계 법령상 보존 의무가 적용되면 해당 기간 동안 분리 보관</li>
            </ul>
            <p className="privacy-detail">블록체인에 직접 기록된 거래는 네트워크 특성상 SAFER가 임의로 수정하거나 삭제할 수 없습니다. 현재 SAFER의 내부 원화 잔액과 거래는 데이터베이스 기록이며, Ethereum 연결은 공개 주소의 소유권 확인에 사용됩니다.</p>
          </section>

          <section id="privacy-sharing">
            <span className="privacy-number">03</span>
            <h2>제3자 제공, 처리위탁 및 국외 이전</h2>
            <p>SAFER는 정보주체의 별도 동의나 법률상 근거 없이 개인정보를 판매하거나 광고 목적으로 제3자에게 제공하지 않습니다.</p>
            <div className="privacy-table-wrap">
              <table>
                <thead><tr><th>서비스 제공자</th><th>처리 업무와 항목</th><th>처리 위치·방법</th></tr></thead>
                <tbody>
                  <tr><td>OpenAI Sites</td><td>사이트 접근 인증, 배포·요청 전달. 인증 신원은 SAFER 서버에서 HMAC 해시로 변환</td><td>접속 시 암호화된 네트워크를 통해 국외 인프라에서 처리될 수 있음</td></tr>
                  <tr><td>Cloudflare</td><td>Workers 실행, D1 데이터베이스, R2 상품 이미지 저장, 보안·전송 처리</td><td>글로벌 인프라에서 암호화된 네트워크를 통해 처리될 수 있음</td></tr>
                  <tr><td>Ethereum 네트워크·RPC 제공자</td><td>사용자가 지갑 연결 또는 온체인 기능을 선택한 경우 공개 주소, 서명 검증 요청, 공개 거래정보 처리</td><td>분산 네트워크 및 설정된 HTTPS RPC로 전송. 블록체인 기록은 공개·영구적일 수 있음</td></tr>
                </tbody>
              </table>
            </div>
            <p className="privacy-detail">정식 공개 운영 시 운영자는 실제 이용하는 공급자, 이전 국가, 이전 일시·방법, 보유기간과 거부 방법을 계약 기준으로 확정하여 이 표를 갱신합니다.</p>
          </section>

          <section id="privacy-destruction">
            <span className="privacy-number">04</span>
            <h2>개인정보의 파기 절차와 방법</h2>
            <p>처리 목적이 달성되거나 삭제 요청이 확인되면 관련 정보를 지체 없이 삭제합니다. 법령이나 분쟁 대응을 위해 보존해야 하는 정보는 다른 정보와 분리하고 접근을 제한합니다.</p>
            <ul>
              <li>데이터베이스 기록은 복구가 어렵도록 삭제 명령을 수행하고 참조 관계를 확인합니다.</li>
              <li>R2 상품 이미지는 연결된 상품 삭제 절차에 따라 객체를 제거합니다.</li>
              <li>세션 쿠키는 로그아웃·만료 시 즉시 무효화하고 서버의 해시 기록을 삭제합니다.</li>
              <li>블록체인에 이미 공개된 정보는 기술적으로 파기할 수 없으므로 온체인 사용 전에 이를 안내합니다.</li>
            </ul>
          </section>

          <section id="privacy-rights">
            <span className="privacy-number">05</span>
            <h2>정보주체의 권리와 행사 방법</h2>
            <p>이용자는 자신의 개인정보에 대한 열람, 정정, 삭제, 처리정지 및 동의 철회를 요청할 수 있습니다. 요청 시 계정 탈취를 막기 위해 현재 세션, 연합 신원 또는 Passkey로 본인 여부를 다시 확인할 수 있습니다.</p>
            <ul>
              <li>소개글과 비밀번호: 마이페이지에서 직접 변경</li>
              <li>Passkey: 마이페이지의 Passkey 관리에서 확인·삭제</li>
              <li>그 밖의 열람·삭제·처리정지: 아래 개인정보 보호 문의 채널로 비공개 요청</li>
            </ul>
            <p className="privacy-detail">다른 이용자의 권리, 거래 무결성 또는 법적 의무를 침해하는 범위에서는 일부 요청이 제한될 수 있으며, 제한 사유를 안내합니다.</p>
          </section>

          <section id="privacy-security">
            <span className="privacy-number">06</span>
            <h2>개인정보의 안전성 확보조치</h2>
            <ul>
              <li>PBKDF2-SHA-256 비밀번호 해시, 세션 토큰 해시, 연합 신원 HMAC 가명화</li>
              <li>HttpOnly·Secure·SameSite 쿠키, CSRF와 동일 출처 검증, 8시간 절대·30분 유휴 세션 만료</li>
              <li>Passkey 일회용 challenge, 고정 RP ID·origin, 사용자 확인과 서명 카운터 검증</li>
              <li>관리자·소유자 권한의 서버 재검증, prepared statement와 입력 길이·형식 제한</li>
              <li>JPEG·PNG·WebP magic byte 검사와 5MB 이미지 제한</li>
              <li>CSP nonce, 보안 헤더, 속도 제한, 민감정보가 제거된 감사 로그와 요청 추적 ID</li>
            </ul>
          </section>

          <section id="privacy-cookies">
            <span className="privacy-number">07</span>
            <h2>쿠키, 행태정보 및 자동화된 조치</h2>
            <p>SAFER는 로그인 세션과 CSRF 방어에 필요한 쿠키만 사용하며, 맞춤형 광고나 제3자 행태 추적 쿠키를 사용하지 않습니다. 브라우저 설정에서 쿠키를 차단할 수 있으나 로그인 기능이 동작하지 않을 수 있습니다.</p>
            <p>동일 대상에 대한 유효 신고가 기준 횟수에 도달하면 상품 노출 제한 또는 계정 휴면 전환이 자동으로 적용될 수 있습니다. 이용자는 개인정보 보호 문의 채널을 통해 검토와 이의를 요청할 수 있으며, 관리자가 신고 사유와 감사 기록을 확인합니다.</p>
          </section>

          <section id="privacy-contact">
            <span className="privacy-number">08</span>
            <h2>개인정보 보호책임자, 문의 및 방침 변경</h2>
            <div className="privacy-contact-card">
              <div><small>개인정보 보호책임</small><strong>SAFER 프로젝트 운영자</strong></div>
              <a className="button primary" href="https://github.com/gogooma125732/secure_coding/security/advisories/new" target="_blank" rel="noreferrer">비공개 문의하기</a>
            </div>
            <p>개인정보나 보안정보를 공개 GitHub Issue에 게시하지 마세요. 비공개 Security Advisory를 통해 요청하면 본인 확인 후 처리 결과를 안내합니다. 정식 서비스 전환 시 담당자의 성명, 전화번호 및 이메일을 이 영역에 추가합니다.</p>
            <p>이 방침은 <b>2026년 7월 26일</b>부터 적용됩니다. 중요한 내용이 변경되면 시행 전에 이 페이지를 통해 알립니다.</p>
            <p className="privacy-reference">작성 기준: <a href="https://www.law.go.kr/법령/개인정보보호법" target="_blank" rel="noreferrer">개인정보 보호법</a> · <a href="https://www.pipc.go.kr/np/cop/bbs/selectBoardArticle.do?bbsId=BS217&mCode=D010030000&nttId=11134" target="_blank" rel="noreferrer">개인정보보호위원회 처리방침 작성지침</a></p>
          </section>
        </div>
      </div>
    </article>
  );
}

function Footer() { return <footer><a className="brand" href="/"><span className="brand-mark">S</span><span>SAFER<small>secure secondhand</small></span></a><p>신뢰를 먼저 설계한 중고거래 플랫폼</p><nav><a href="/market">마켓</a><a href="/signup">회원가입</a><a href="/login">로그인</a><a href="/privacy">개인정보처리방침</a></nav><small>© 2026 SAFER · Secure Software Engineering Project</small></footer>; }

async function api<T = Record<string, unknown>>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!(init.body instanceof FormData) && init.body !== undefined) headers.set("content-type", "application/json");
  const method = (init.method ?? "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = readCookie(location.protocol === "https:" ? "__Host-csrf" : "csrf");
    if (csrf) headers.set("x-csrf-token", csrf);
  }
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  const data = await response.json().catch(() => ({})) as { error?: { code?: string; message?: string } } & T;
  if (!response.ok) {
    if (
      response.status === 401 &&
      data.error?.code === "SESSION_EXPIRED" &&
      !["/login", "/signup"].includes(window.location.pathname)
    ) {
      window.location.replace("/login?reason=session-expired");
    }
    throw new Error(data.error?.message || httpErrorMessage(response.status));
  }
  return data;
}

function validateProductImage(value: FormDataEntryValue | null): string {
  if (!(value instanceof File) || value.size === 0) return "상품 이미지를 선택해 주세요. JPEG, PNG, WebP 형식만 등록할 수 있습니다.";
  const extension = value.name.split(".").pop()?.toLowerCase() ?? "";
  const errors: string[] = [];
  if (!ALLOWED_CLIENT_IMAGE_TYPES.has(value.type) || !ALLOWED_CLIENT_IMAGE_EXTENSIONS.has(extension)) {
    errors.push("지원하지 않는 이미지 형식입니다. JPEG(.jpg, .jpeg), PNG(.png), WebP(.webp)만 등록할 수 있습니다.");
  }
  if (value.size > MAX_CLIENT_IMAGE_BYTES) {
    errors.push(`이미지 크기는 5MB 이하여야 합니다. 선택한 파일은 ${formatFileSize(value.size)}입니다.`);
  }
  return errors.join(" ");
}

function formatFileSize(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

function compactPublicAlias(value: string): string {
  if (value.length <= 22) return value;
  return `${value.slice(0, 12)}…${value.slice(-6)}`;
}

function httpErrorMessage(status: number): string {
  if (status === 413) return "업로드 파일이 너무 큽니다. JPEG, PNG, WebP 형식의 5MB 이하 이미지를 선택해 주세요.";
  if (status === 415) return "지원하지 않는 파일 형식입니다. JPEG, PNG 또는 WebP 이미지를 선택해 주세요.";
  return "요청을 처리하지 못했습니다.";
}

function readCookie(name: string): string {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const value = part.trim();
    if (!value.startsWith(prefix)) continue;
    try {
      return decodeURIComponent(value.slice(prefix.length));
    } catch {
      return "";
    }
  }
  return "";
}
function money(value: number): string { return new Intl.NumberFormat("ko-KR", { style: "currency", currency: "KRW", maximumFractionDigits: 0 }).format(value); }
function formatTime(value: number): string { return new Intl.DateTimeFormat("ko-KR", { hour: "2-digit", minute: "2-digit" }).format(new Date(value)); }
function formatDate(value: number): string { return new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
function shortWalletId(value: string): string { return `${value.slice(0, 12)}…${value.slice(-8)}`; }
function tradeStatusLabel(value: ProductTrade["status"]): string { return value === "requested" ? "승인 대기" : value === "accepted" ? "결제 대기" : value === "completed" ? "거래 완료" : "취소됨"; }
function errorMessage(error: unknown): string { return error instanceof Error ? error.message : "요청을 처리하지 못했습니다."; }

function ethereumProviderErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (!error || typeof error !== "object") return "Ethereum 지갑 요청을 처리하지 못했습니다.";
  const candidate = error as { code?: unknown; message?: unknown };
  const code = typeof candidate.code === "number" ? candidate.code : Number(candidate.code);
  if (code === 4001) return "지갑 연결 또는 서명 요청이 취소되었습니다.";
  if (code === -32002) return "지갑에서 처리 중인 요청이 있습니다. 지갑 창을 확인한 뒤 완료해 주세요.";
  if (code === 4900) return "Ethereum 지갑이 네트워크와 연결되어 있지 않습니다.";
  if (code === 4901) return "현재 지갑이 선택한 Ethereum 네트워크에 연결되어 있지 않습니다.";
  if (code === 4902) return "지갑에 필요한 Ethereum 네트워크가 등록되어 있지 않습니다.";
  const message = typeof candidate.message === "string" ? candidate.message.toLowerCase() : "";
  if (message.includes("locked")) return "Ethereum 지갑의 잠금을 해제한 뒤 다시 시도해 주세요.";
  if (message.includes("pending") || message.includes("already processing")) {
    return "지갑에서 처리 중인 요청이 있습니다. 지갑 창을 확인한 뒤 완료해 주세요.";
  }
  if (message.includes("reject") || message.includes("denied")) return "지갑 연결 또는 서명 요청이 취소되었습니다.";
  return "Ethereum 지갑 요청을 처리하지 못했습니다. 지갑 잠금과 네트워크 상태를 확인해 주세요.";
}
