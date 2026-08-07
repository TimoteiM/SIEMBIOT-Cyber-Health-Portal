"use client";

import { useCallback, useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { apiErrorKey } from "../../../../lib/api-errors";
import type { MessageKey } from "../../../../lib/i18n";
import { useLocalization } from "../../../../lib/i18n/provider";
import { apiRequest, loadSession } from "../../../../lib/secure-client";

type Maturity = components["schemas"]["MaturityResponse"];
type Section = components["schemas"]["SectionResponse"];
type Question = components["schemas"]["QuestionResponse"];
type Answer = NonNullable<Question["answer"]>;
type Corroboration = NonNullable<Question["corroboration"]>;

/**
 * The order of the ladder comes from the server, which reads it from the versioned
 * policy catalogue. Hard-coding it here would let the interface offer a rung the
 * scoring does not know about, or omit one it does.
 */
const ANSWER_KEYS: Record<Answer, MessageKey> = {
  absent: "maturity.answer.absent",
  informal: "maturity.answer.informal",
  documented: "maturity.answer.documented",
  verified: "maturity.answer.verified",
  unknown: "maturity.answer.unknown",
  not_applicable: "maturity.answer.not_applicable",
};

/**
 * The paragraph letter out of a citation like "Article 21(2)(g)".
 *
 * The catalogue stores the canonical English citation because that is what the API and
 * its tests key on. Rendering it verbatim under a Romanian label produced "NIS2,
 * articolul Article 21(2)(g)" -- the word "article" twice, in two languages. Only the
 * letter varies between sections, so only the letter crosses into the message.
 */
function paragraphLetter(reference: string): string {
  return /\(([a-z])\)\s*$/.exec(reference)?.[1] ?? reference;
}

const CORROBORATION_KEYS: Record<Corroboration, MessageKey> = {
  contradicted: "maturity.contradictedNotice",
  understated: "maturity.understatedNotice",
  consistent: "maturity.consistentNotice",
  not_observed: "maturity.notObservedNotice",
};

function QuestionRow({
  question,
  organizationId,
  onAnswered,
  onMessage,
}: {
  question: Question;
  organizationId: string;
  onAnswered: (next: Maturity) => void;
  onMessage: (key: MessageKey) => void;
}) {
  const { t, pick, formatDateTime } = useLocalization();
  const [busy, setBusy] = useState(false);

  async function choose(answer: string) {
    if (!answer) return;
    setBusy(true);
    try {
      onAnswered(
        await apiRequest<Maturity>(
          `/api/v1/organizations/${organizationId}/maturity/answers/${question.question_id}`,
          { method: "PUT", body: JSON.stringify({ answer }) },
        ),
      );
      onMessage("maturity.saved");
    } catch (error) {
      onMessage(apiErrorKey(error, "maturity.saveFailed"));
    } finally {
      setBusy(false);
    }
  }

  const selectId = `q-${question.question_id}`;
  return (
    <li className="maturity-question">
      <label htmlFor={selectId}>{pick(question.title_ro, question.title_en)}</label>
      <p className="muted">{pick(question.help_ro, question.help_en)}</p>

      <select
        id={selectId}
        value={question.answer ?? ""}
        disabled={busy}
        onChange={(event) => choose(event.target.value)}
      >
        <option value="">{t("maturity.notAnswered")}</option>
        {(Object.keys(ANSWER_KEYS) as Answer[]).map((answer) => (
          <option key={answer} value={answer}>
            {t(ANSWER_KEYS[answer])}
          </option>
        ))}
      </select>

      {question.answered_by_display_name && question.answered_at && (
        <small className="muted">
          {t("maturity.answeredBy", {
            name: question.answered_by_display_name,
            when: formatDateTime(question.answered_at),
          })}
        </small>
      )}

      {/*
        Where the platform can see the same subject, the relationship gets a sentence.
        A disagreement is given the room a caveat gets elsewhere in this product,
        because it is the most useful thing on the row: the organisation believes one
        thing and the evidence says another, and neither number alone says that.
      */}
      {question.corroboration === "contradicted" && (
        <div className="remediation-caveat" role="note">
          <p>{t("maturity.contradictedNotice")}</p>
        </div>
      )}
      {question.corroboration && question.corroboration !== "contradicted" && (
        <p className="muted maturity-observed">
          {t(CORROBORATION_KEYS[question.corroboration])}
        </p>
      )}
    </li>
  );
}

function SectionBlock({
  section,
  organizationId,
  onAnswered,
  onMessage,
}: {
  section: Section;
  organizationId: string;
  onAnswered: (next: Maturity) => void;
  onMessage: (key: MessageKey) => void;
}) {
  const { t, pick, formatNumber } = useLocalization();
  return (
    <section className="maturity-section" aria-labelledby={`s-${section.section_id}`}>
      <div className="section-heading">
        <div>
          <h2 id={`s-${section.section_id}`}>{pick(section.title_ro, section.title_en)}</h2>
          {/*
            The legal reference is shown because "why am I being asked this" has an
            answer, and it is not "because a security team thought it was a good idea".

            Not the `eyebrow` class, which uppercases: that turns Article 21(2)(a) into
            21(2)(A) and a citation that quotes the wrong letter is a wrong citation.
          */}
          <p className="muted maturity-reference">
            {t("maturity.reference", { letter: paragraphLetter(section.nis2_reference) })}
          </p>
        </div>
        <p className="muted">
          {section.percentage === null || section.percentage === undefined
            ? t("maturity.sectionUnanswered")
            : t("maturity.sectionScore", {
                percentage: formatNumber(section.percentage),
              })}
        </p>
      </div>

      <ul className="maturity-questions">
        {(section.questions ?? []).map((question) => (
          <QuestionRow
            key={question.question_id}
            question={question}
            organizationId={organizationId}
            onAnswered={onAnswered}
            onMessage={onMessage}
          />
        ))}
      </ul>
    </section>
  );
}

export default function MaturityPanel({ organizationId }: { organizationId: string }) {
  const [data, setData] = useState<Maturity | null>(null);
  const [message, setMessage] = useState<MessageKey | null>("maturity.loading");
  const { t, pick, formatNumber } = useLocalization();

  const reload = useCallback(async () => {
    await loadSession();
    setData(await apiRequest<Maturity>(`/api/v1/organizations/${organizationId}/maturity`));
    setMessage(null);
  }, [organizationId]);

  useEffect(() => {
    reload().catch((error: unknown) => setMessage(apiErrorKey(error, "maturity.loadFailed")));
  }, [reload]);

  const applicable = data ? data.answered_count + data.unanswered_count : 0;

  return (
    <section className="panel" aria-labelledby="maturity-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{t("maturity.eyebrow")}</p>
          <h1 id="maturity-title">{t("maturity.title")}</h1>
        </div>
      </div>

      <p>{t("maturity.intro")}</p>

      {data && (
        <>
          {/*
            The notice the questionnaire carries about itself, in the reader's language,
            before any of its questions. It says these are declarations rather than
            findings -- which is the one thing somebody reading a percentage later will
            not infer on their own.
          */}
          <p className="hint">{pick(data.notice_ro, data.notice_en)}</p>
          {data.review_status !== "reviewed" && (
            <p className="hint">{t("maturity.draftNotice")}</p>
          )}

          <section className="maturity-summary" aria-labelledby="maturity-summary-title">
            {/*
              Withheld rather than caveated below the floor. A percentage next to a
              warning is still a percentage, and readers keep the number and drop the
              warning -- the same reason the technical side removes the band instead of
              annotating it.
            */}
            <h2 id="maturity-summary-title" className="maturity-verdict">
              {data.comparable && data.self_declared_percentage !== null
                ? `${t("maturity.declared")}: ${formatNumber(
                    data.self_declared_percentage ?? 0,
                  )}%`
                : t("maturity.withheld")}
            </h2>

            {!data.comparable && (
              <p className="muted">
                {data.incomparable_reason === "nothing_applicable"
                  ? t("maturity.nothingApplicable")
                  : t("maturity.insufficientCompleteness", {
                      floor: data.minimum_completeness_percentage,
                    })}
              </p>
            )}

            {/*
              Stated next to the result rather than in help text somewhere else. The
              mistake this prevents -- averaging a declaration with a measurement -- is
              made by a reader looking at exactly this number.
            */}
            <p className="muted">{t("maturity.declaredExplained")}</p>

            <p className="muted">
              {t("maturity.completeness")}:{" "}
              {formatNumber(data.completeness_percentage)}% —{" "}
              {t("maturity.answered", { answered: data.answered_count, total: applicable })}
            </p>
            <p className="muted">{t("maturity.unknownExplained")}</p>

            {data.contradicted_count > 0 && (
              <div className="remediation-caveat" role="note">
                <p>{t("maturity.contradicted", { count: data.contradicted_count })}</p>
              </div>
            )}
          </section>

          {(data.sections ?? []).map((section) => (
            <SectionBlock
              key={section.section_id}
              section={section}
              organizationId={organizationId}
              onAnswered={setData}
              onMessage={setMessage}
            />
          ))}
        </>
      )}

      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
