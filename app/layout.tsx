import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { headers } from "next/headers";
import { BrowserSecurityBoundary } from "./browser-security-boundary";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const forwardedHost = requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host") ?? "safer-market.example";
  const host = trustedMetadataHost(forwardedHost);
  const forwardedProtocol = requestHeaders.get("x-forwarded-proto");
  const protocol = forwardedProtocol === "http" || forwardedProtocol === "https" ? forwardedProtocol : host.startsWith("localhost") ? "http" : "https";
  const metadataBase = new URL(`${protocol}://${host}`);
  const title = "SAFER — 안전한 중고거래";
  const description = "신뢰를 먼저 설계한 시큐어 중고거래 플랫폼";
  return {
    metadataBase,
    title: { default: title, template: "%s | SAFER" },
    description,
    openGraph: { title, description, type: "website", images: [{ url: new URL("/og.png", metadataBase), width: 1734, height: 910, alt: "SAFER 보안 중고거래 플랫폼" }] },
    twitter: { card: "summary_large_image", title, description, images: [new URL("/og.png", metadataBase)] },
  };
}

function trustedMetadataHost(value: string): string {
  const host = value.trim().toLowerCase();
  const local = /^(?:localhost|127\.0\.0\.1)(?::\d{1,5})?$/u.test(host);
  const sitesDeployment = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+chatgpt\.site$/u.test(host);
  return local || sitesDeployment ? host : "safer-secure-market-2026.hippipo779.chatgpt.site";
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ko">
      <body
        className={`${geistSans.variable} ${geistMono.variable}`}
      >
        <BrowserSecurityBoundary>{children}</BrowserSecurityBoundary>
      </body>
    </html>
  );
}
