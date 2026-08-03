import DomainDetail from "./domain-detail";

export default async function DomainDetailPage({
  params,
}: {
  params: Promise<{ organizationId: string; domainId: string }>;
}) {
  const { organizationId, domainId } = await params;
  return <DomainDetail organizationId={organizationId} domainId={domainId} />;
}
