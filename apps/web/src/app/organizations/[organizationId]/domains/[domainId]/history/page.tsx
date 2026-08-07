import HistoryPanel from "./history-panel";

export default async function HistoryPage({
  params,
}: {
  params: Promise<{ organizationId: string; domainId: string }>;
}) {
  const { organizationId, domainId } = await params;
  return <HistoryPanel organizationId={organizationId} domainId={domainId} />;
}
