"use client";

import { useCallback, useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { apiErrorKey } from "../../../../../../lib/api-errors";
import type { MessageKey } from "../../../../../../lib/i18n";
import { useLocalization } from "../../../../../../lib/i18n/provider";
import { apiRequest, loadSession } from "../../../../../../lib/secure-client";

type History = components["schemas"]["DomainHistoryResponse"];
type Point = components["schemas"]["HistoryPointResponse"];

const CHART_HEIGHT = 120;
const CHART_WIDTH = 640;
const PADDING = 16;

/**
 * The chart is always drawn against the full 0–100 range rather than against the range
 * of the data. Auto-scaling would turn a two-point wobble into a dramatic climb, which
 * is the same misrepresentation this product refuses everywhere else.
 */
function pointPosition(point: Point, index: number, total: number) {
  const x =
    total <= 1
      ? CHART_WIDTH / 2
      : PADDING + (index / (total - 1)) * (CHART_WIDTH - PADDING * 2);
  const y = PADDING + (1 - point.score / 100) * (CHART_HEIGHT - PADDING * 2);
  return { x, y };
}

export default function HistoryPanel({
  organizationId,
  domainId,
}: {
  organizationId: string;
  domainId: string;
}) {
  const [data, setData] = useState<History | null>(null);
  const [message, setMessage] = useState<MessageKey | null>("history.loading");
  const { t, formatDateTime, formatNumber, pick } = useLocalization();

  const reload = useCallback(async () => {
    await loadSession();
    setData(
      await apiRequest<History>(
        `/api/v1/organizations/${organizationId}/domains/${domainId}/history`,
      ),
    );
    setMessage(null);
  }, [organizationId, domainId]);

  useEffect(() => {
    reload().catch((error: unknown) => setMessage(apiErrorKey(error, "history.loadFailed")));
  }, [reload]);

  const points = data?.points ?? [];
  const change = data?.change ?? null;

  return (
    <section className="panel" aria-labelledby="history-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{t("history.eyebrow")}</p>
          <h1 id="history-title">{t("history.title")}</h1>
        </div>
      </div>

      {data && points.length === 0 && <p className="hint">{t("history.none")}</p>}
      {data && points.length === 1 && <p className="hint">{t("history.single")}</p>}

      {points.length >= 2 && (
        <figure className="history-chart">
          <svg
            viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`}
            role="img"
            aria-labelledby="history-chart-title"
            preserveAspectRatio="none"
          >
            <title id="history-chart-title">{t("history.chartLabel")}</title>
            {/*
              Drawn as segments between adjacent runs that both cleared the coverage
              floor, not as one continuous line.

              A line is a stronger claim than a circle's fill: joining a run that saw
              5% of the surface to one that saw 90% draws a dramatic decline that never
              happened, and no amount of hollow marker undoes it. Where the run either
              side cannot be compared, there is simply no line -- which is what "we
              cannot tell you how this moved" looks like.
            */}
            {points.slice(1).map((point, offset) => {
              const index = offset + 1;
              const previous = points[offset];
              if (!previous.coverage_sufficient || !point.coverage_sufficient) return null;
              const from = pointPosition(previous, offset, points.length);
              const to = pointPosition(point, index, points.length);
              return (
                <line
                  key={point.assessment_id}
                  className="history-line"
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                />
              );
            })}
            {points.map((point, index) => {
              const { x, y } = pointPosition(point, index, points.length);
              return (
                <circle
                  key={point.assessment_id}
                  cx={x}
                  cy={y}
                  r={4}
                  /*
                    A run below the coverage floor is drawn hollow. It has a number but
                    not a result, and rendering it identically to the others would put
                    it on the same footing as a run we would actually stand behind.
                  */
                  className={
                    point.coverage_sufficient ? "history-point" : "history-point thin"
                  }
                />
              );
            })}
          </svg>
          {/*
            The same data as a list, because an SVG line is not readable by a screen
            reader and "score over time" is not a description anybody can act on.
          */}
          <figcaption>
            <ul className="history-points">
              {points.map((point) => (
                <li key={point.assessment_id}>
                  {t("history.pointLabel", {
                    score: formatNumber(point.score),
                    coverage: formatNumber(point.coverage_percentage),
                    when: formatDateTime(point.completed_at),
                  })}
                </li>
              ))}
            </ul>
          </figcaption>
        </figure>
      )}

      {change && (
        <section aria-labelledby="change-title">
          <h2 id="change-title">{t("history.sinceLast")}</h2>

          {/*
            When the two runs did not see the same amount, the reason comes before the
            numbers. A reader who meets "+40" first has already drawn a conclusion by
            the time they reach the caveat.
          */}
          {!change.comparable && (
            <div className="remediation-caveat" role="note">
              <p>
                {change.incomparable_reason === "insufficient_coverage"
                  ? t("history.incomparableInsufficient")
                  : t("history.incomparableCoverage", {
                      delta: formatNumber(Math.abs(change.coverage_delta)),
                    })}
              </p>
            </div>
          )}

          <p className={change.comparable ? "score-verdict" : "muted"}>
            {change.score_delta > 0
              ? t("history.scoreUp", { delta: formatNumber(change.score_delta) })
              : change.score_delta < 0
                ? t("history.scoreDown", {
                    delta: formatNumber(Math.abs(change.score_delta)),
                  })
                : t("history.scoreSame")}
          </p>
          {change.comparable && change.coverage_delta !== 0 && (
            <p className="muted">
              {t("history.coverageChange", {
                delta: formatNumber(change.coverage_delta),
              })}
            </p>
          )}

          {(change.resolved ?? []).length > 0 && (
            <>
              <h3>{t("history.resolved", { count: (change.resolved ?? []).length })}</h3>
              <ul className="card-list">
                {(change.resolved ?? []).map((item) => (
                  <li key={item.check_id}>
                    <span className="badge success">✓</span>
                    <span>{pick(item.title_ro, item.title_en)}</span>
                  </li>
                ))}
              </ul>
            </>
          )}

          {(change.opened ?? []).length > 0 && (
            <>
              <h3>{t("history.opened", { count: (change.opened ?? []).length })}</h3>
              <ul className="card-list">
                {(change.opened ?? []).map((item) => (
                  <li key={item.check_id}>
                    <span className={`badge ${item.severity === "low" ? "neutral" : "danger"}`}>
                      {t(`severity.${item.severity}` as MessageKey)}
                    </span>
                    <span>{pick(item.title_ro, item.title_en)}</span>
                  </li>
                ))}
              </ul>
            </>
          )}

          {change.unchanged_count > 0 && (
            <p className="muted">
              {t("history.unchanged", { count: change.unchanged_count })}
            </p>
          )}
        </section>
      )}

      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
