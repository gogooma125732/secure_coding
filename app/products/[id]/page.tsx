import { MarketplaceApp } from "../../marketplace-client";

export default async function ProductPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <MarketplaceApp view="product" resourceId={id} />;
}
