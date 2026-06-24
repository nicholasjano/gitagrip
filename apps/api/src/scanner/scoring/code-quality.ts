// combines Lizard + jscpd partial scores into published code_quality category

import {
  clampScore,
  notApplicableScore,
  type CategoryScore,
  type PartialToolScore,
} from '../types.js';

export function combineCodeQuality(
  lizard: PartialToolScore,
  jscpd: PartialToolScore,
  applicable: boolean,
): CategoryScore {
  if (!applicable) {
    return notApplicableScore('code_quality', 'No supported source files detected');
  }

  const lizardOk = !lizard.failed;
  const jscpdOk = !jscpd.failed;

  if (!lizardOk && !jscpdOk) {
    const reasons: string[] = [];
    if (lizard.failed) reasons.push(`lizard ${lizard.failureReason ?? 'failed'}`);
    if (jscpd.failed) reasons.push(`jscpd ${jscpd.failureReason ?? 'failed'}`);
    return {
      category: 'code_quality',
      score: 0,
      applicable: true,
      message: `Tool failed: ${reasons.join('; ')}`,
      findingCount: 0,
    };
  }

  let score: number;
  const parts: string[] = [];
  const unavailable: string[] = [];

  if (lizardOk && jscpdOk) {
    score = clampScore(lizard.score * 0.6 + jscpd.score * 0.4);
    parts.push(lizard.detail, jscpd.detail);
  } else if (lizardOk) {
    score = lizard.score;
    parts.push(lizard.detail);
    unavailable.push('duplication unavailable');
  } else {
    score = jscpd.score;
    parts.push(jscpd.detail);
    unavailable.push('complexity unavailable');
  }

  let message = parts.filter(Boolean).join(', ');
  if (unavailable.length > 0) {
    message = message ? `${message} (${unavailable.join(', ')})` : unavailable.join(', ');
  }

  return {
    category: 'code_quality',
    score,
    applicable: true,
    message,
    findingCount: 0,
  };
}
