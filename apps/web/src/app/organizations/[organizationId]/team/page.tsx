import TeamPanel from "./team-panel";

export default async function TeamPage({
  params,
}: {
  params: Promise<{ organizationId: string }>;
}) {
  const { organizationId } = await params;
  return <TeamPanel organizationId={organizationId} />;
}
