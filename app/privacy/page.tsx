import type { Metadata } from "next";
import { MarketplaceApp } from "../marketplace-client";

export const metadata: Metadata = {
  title: "개인정보처리방침",
  description: "SAFER가 처리하는 개인정보의 항목, 목적, 보유기간과 이용자 권리를 안내합니다.",
};

export default function PrivacyPage() {
  return <MarketplaceApp view="privacy" />;
}
