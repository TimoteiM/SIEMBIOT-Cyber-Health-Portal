import MaturityPanel from "./maturity-panel";

export default async function MaturityPage({
  params,
}: {
  params: Promise<{ organizationId: string }>;
}) {
  const { organizationId } = await params;
  return <MaturityPanel organizationId={organizationId} />;
}
