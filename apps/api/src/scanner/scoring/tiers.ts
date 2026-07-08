// tier weights for overall score aggregation — critical 3x / high 2x / standard 1x

import { tierForCategory, type ScanCategoryName } from '@gitagrip/shared';

const TIER_WEIGHT = { critical: 3, high: 2, standard: 1 } as const;

export function weightForCategory(category: ScanCategoryName): number {
  return TIER_WEIGHT[tierForCategory(category)];
}
