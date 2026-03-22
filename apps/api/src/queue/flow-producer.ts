// batch job creation logic
// creates parent job in batch-queue + many child jobs in scan-queue in one atomic operation

import { FlowProducer } from 'bullmq';
import { bullRedis } from '../db/bull-redis.js';

export const flowProducer = new FlowProducer({
  connection: bullRedis,
});
