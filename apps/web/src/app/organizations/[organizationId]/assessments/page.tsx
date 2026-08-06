import AssessmentPanel from "./assessment-panel";

export default async function AssessmentsPage({
  params,
}: {
  params: Promise<{ organizationId: string }>;
}) {
  const { organizationId } = await params;
  return <AssessmentPanel organizationId={organizationId} />;
}
