import DomainPanel from "./domain-panel";

export default async function DomainsPage({
  params,
}: {
  params: Promise<{ organizationId: string }>;
}) {
  const { organizationId } = await params;
  return <DomainPanel organizationId={organizationId} />;
}
