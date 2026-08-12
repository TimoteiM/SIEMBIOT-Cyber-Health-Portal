import SettingsPanel from "./settings-panel";

export default async function SettingsPage({
  params,
}: {
  params: Promise<{ organizationId: string }>;
}) {
  const { organizationId } = await params;
  return <SettingsPanel organizationId={organizationId} />;
}
