import FindingsPanel from "./findings-panel";

export default async function FindingsPage({
  params,
}: {
  params: Promise<{ organizationId: string; domainId: string }>;
}) {
  const { organizationId, domainId } = await params;
  return <FindingsPanel organizationId={organizationId} domainId={domainId} />;
}
