import AuditPanel from "./audit-panel";

export default async function AuditPage({
  params,
}: {
  params: Promise<{ organizationId: string }>;
}) {
  const { organizationId } = await params;
  return <AuditPanel organizationId={organizationId} />;
}
