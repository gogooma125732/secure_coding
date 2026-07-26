import {
  createPublicClient,
  getAddress,
  http,
  isAddress,
  verifyMessage as verifyEoaMessage,
  type Address,
  type Chain,
} from "viem";
import { mainnet, sepolia } from "viem/chains";

import { getEnv } from "./db";
import { HttpError } from "./security";

const SUPPORTED_CHAINS = new Map<number, Chain>([
  [mainnet.id, mainnet],
  [sepolia.id, sepolia],
]);

export type Web3Config = {
  chainId: 1 | 11155111;
  chainName: string;
  rpcUrl: string | null;
  escrowAddress: Address | null;
  paymentTokenAddress: Address | null;
  walletLinkEnabled: boolean;
  settlementEnabled: boolean;
  confirmations: number;
};

export function web3Config(): Web3Config {
  const environment = getEnv();
  const rawChainId = environment.WEB3_CHAIN_ID?.trim() || String(sepolia.id);
  const chainId = Number(rawChainId);
  if (chainId !== mainnet.id && chainId !== sepolia.id) {
    throw new HttpError(503, "WEB3_CONFIGURATION_INVALID", "지원하지 않는 Ethereum 네트워크 설정입니다.");
  }

  const rpcUrl = validatedRpcUrl(environment.WEB3_RPC_URL, environment.WEB3_RPC_HOST_ALLOWLIST);
  const escrowAddress = optionalAddress(environment.WEB3_ESCROW_ADDRESS, "에스크로 컨트랙트");
  const paymentTokenAddress = optionalAddress(environment.WEB3_PAYMENT_TOKEN_ADDRESS, "결제 토큰");
  const confirmations = boundedInteger(environment.WEB3_CONFIRMATIONS, chainId === mainnet.id ? 12 : 3, 1, 64);
  const chain = SUPPORTED_CHAINS.get(chainId)!;

  return {
    chainId,
    chainName: chain.name,
    rpcUrl,
    escrowAddress,
    paymentTokenAddress,
    walletLinkEnabled: true,
    settlementEnabled: Boolean(rpcUrl && escrowAddress && paymentTokenAddress),
    confirmations,
  };
}

export function publicWeb3Config(): Omit<Web3Config, "rpcUrl"> {
  const config = web3Config();
  return {
    chainId: config.chainId,
    chainName: config.chainName,
    escrowAddress: config.escrowAddress,
    paymentTokenAddress: config.paymentTokenAddress,
    walletLinkEnabled: config.walletLinkEnabled,
    settlementEnabled: config.settlementEnabled,
    confirmations: config.confirmations,
  };
}

export function normalizeWalletAddress(value: unknown): { address: Address; addressKey: string } {
  if (typeof value !== "string" || value.length !== 42 || !isAddress(value, { strict: false })) {
    throw new HttpError(400, "INVALID_WALLET_ADDRESS", "올바른 Ethereum 지갑 주소를 입력해 주세요.");
  }
  const address = getAddress(value);
  return { address, addressKey: address.toLowerCase() };
}

export function createSiweMessage(request: Request, address: Address, nonce: string, expiresAt: number): string {
  const url = new URL(request.url);
  const origin = canonicalOrigin(url);
  const issuedAt = new Date().toISOString();
  const expirationTime = new Date(expiresAt).toISOString();
  const { chainId } = web3Config();
  return `${url.host} wants you to sign in with your Ethereum account:\n${address}\n\nSAFER 계정에 이 지갑 주소를 연결합니다. 이 서명은 송금 권한이나 자산 이전 권한을 부여하지 않습니다.\n\nURI: ${origin}/wallet\nVersion: 1\nChain ID: ${chainId}\nNonce: ${nonce}\nIssued At: ${issuedAt}\nExpiration Time: ${expirationTime}`;
}

export async function verifyWalletOwnership(
  address: Address,
  message: string,
  signature: `0x${string}`,
): Promise<"eoa" | "contract"> {
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature) && !/^0x[0-9a-fA-F]+$/.test(signature)) {
    throw new HttpError(400, "INVALID_WALLET_SIGNATURE", "지갑 서명 형식이 올바르지 않습니다.");
  }

  try {
    if (await verifyEoaMessage({ address, message, signature })) return "eoa";
  } catch {
    // Contract-account verification below is intentionally isolated from EOA errors.
  }

  const config = web3Config();
  if (!config.rpcUrl) {
    throw new HttpError(503, "WEB3_RPC_UNAVAILABLE", "스마트 계정 서명 검증을 위한 Ethereum RPC가 설정되지 않았습니다.");
  }
  const chain = SUPPORTED_CHAINS.get(config.chainId)!;
  const client = createPublicClient({ chain, transport: http(config.rpcUrl, { timeout: 5_000, retryCount: 1 }) });
  try {
    const valid = await client.verifyMessage({ address, message, signature });
    if (!valid) throw new Error("signature mismatch");
    return "contract";
  } catch {
    throw new HttpError(401, "INVALID_WALLET_SIGNATURE", "지갑 소유권 서명을 확인할 수 없습니다.");
  }
}

function canonicalOrigin(url: URL): string {
  if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
    throw new HttpError(400, "INVALID_ORIGIN", "HTTPS 환경에서 지갑을 연결해 주세요.");
  }
  return url.origin;
}

function optionalAddress(value: string | undefined, label: string): Address | null {
  const text = value?.trim();
  if (!text) return null;
  if (!isAddress(text, { strict: false })) {
    throw new HttpError(503, "WEB3_CONFIGURATION_INVALID", `${label} 주소 설정이 올바르지 않습니다.`);
  }
  return getAddress(text);
}

function validatedRpcUrl(value: string | undefined, allowlistValue: string | undefined): string | null {
  const text = value?.trim();
  if (!text) return null;
  if (text.length > 2048) throw new HttpError(503, "WEB3_CONFIGURATION_INVALID", "Ethereum RPC 설정이 너무 깁니다.");
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new HttpError(503, "WEB3_CONFIGURATION_INVALID", "Ethereum RPC URL 설정이 올바르지 않습니다.");
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if ((!local && url.protocol !== "https:") || (local && url.protocol !== "http:" && url.protocol !== "https:")) {
    throw new HttpError(503, "WEB3_CONFIGURATION_INVALID", "Ethereum RPC는 HTTPS 연결만 사용할 수 있습니다.");
  }
  if (url.username || url.password || url.hash) {
    throw new HttpError(503, "WEB3_CONFIGURATION_INVALID", "Ethereum RPC URL에 사용자 정보나 fragment를 포함할 수 없습니다.");
  }
  const allowedHosts = new Set((allowlistValue ?? "").split(",").map((host) => host.trim().toLowerCase()).filter(Boolean));
  if (!local && (!allowedHosts.size || !allowedHosts.has(url.hostname.toLowerCase()))) {
    throw new HttpError(503, "WEB3_CONFIGURATION_INVALID", "Ethereum RPC 호스트가 허용 목록에 없습니다.");
  }
  return url.toString();
}

function boundedInteger(value: string | undefined, fallback: number, minimum: number, maximum: number): number {
  if (!value?.trim()) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new HttpError(503, "WEB3_CONFIGURATION_INVALID", "Ethereum 확인 블록 수 설정이 올바르지 않습니다.");
  }
  return parsed;
}
