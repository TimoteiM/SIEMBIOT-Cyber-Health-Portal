import AssetReviewPanel from "./asset-review-panel";

export default async function AssetsPage({
  params,
}: {
  params: Promise<{ organizationId: string; domainId: string }>;
}) {
  const { organizationId, domainId } = await params;
  return <AssetReviewPanel organizationId={organizationId} domainId={domainId} />;
}
