import { expect } from '@playwright/test';

function metricValue(metrics, name) {
  return metrics.find((item) => item.name === name)?.value ?? 0;
}

function slope(values) {
  if (values.length < 2) return 0;
  const meanX = (values.length - 1) / 2;
  const meanY = values.reduce((sum, value) => sum + value, 0) / values.length;
  let numerator = 0;
  let denominator = 0;
  for (let index = 0; index < values.length; index += 1) {
    const dx = index - meanX;
    numerator += dx * (values[index] - meanY);
    denominator += dx * dx;
  }
  return denominator === 0 ? 0 : numerator / denominator;
}

export async function chromiumSession(page) {
  const session = await page.context().newCDPSession(page);
  await session.send('Performance.enable');
  await session.send('HeapProfiler.enable');
  return session;
}

export async function collectGarbage(session) {
  await session.send('HeapProfiler.collectGarbage');
  await new Promise((resolve) => setTimeout(resolve, 50));
}

export async function sample(session) {
  const [heap, performance, dom] = await Promise.all([
    session.send('Runtime.getHeapUsage'),
    session.send('Performance.getMetrics'),
    session.send('Memory.getDOMCounters'),
  ]);
  return {
    heapUsed: heap.usedSize,
    backingStorage: heap.backingStorageSize ?? 0,
    taskDuration: metricValue(performance.metrics, 'TaskDuration'),
    jsEventListeners: metricValue(performance.metrics, 'JSEventListeners'),
    documents: dom.documents,
    nodes: dom.nodes,
  };
}

export async function measureProfile(page, profile, workload, label) {
  const session = await chromiumSession(page);
  for (let index = 0; index < profile.warmup; index += 1) await workload(index);
  await collectGarbage(session);
  const baseline = await sample(session);
  const batches = [];
  for (let batch = 0; batch < profile.batches; batch += 1) {
    for (let index = 0; index < profile.iterationsPerBatch; index += 1) {
      await workload(index);
    }
    await collectGarbage(session);
    batches.push(await sample(session));
  }
  await collectGarbage(session);
  const idleStart = await sample(session);
  const idleMs = 3000;
  await page.waitForTimeout(idleMs);
  const idleEnd = await sample(session);
  await session.detach();

  const heapValues = batches.map((value) => value.heapUsed);
  const backingValues = batches.map((value) => value.backingStorage);
  const heapGrowth = Math.max(0, ...heapValues.map((value) => value - baseline.heapUsed));
  const backingGrowth = Math.max(0, ...backingValues.map((value) => value - baseline.backingStorage));
  const heapSlope = Math.max(0, slope(heapValues));
  const backingSlope = Math.max(0, slope(backingValues));
  const domGrowth = Math.max(
    0,
    ...batches.map((value) => Math.max(
      value.nodes - baseline.nodes,
      value.documents - baseline.documents,
      value.jsEventListeners - baseline.jsEventListeners,
    )),
  );
  const idleCpuRatio = Math.max(0, idleEnd.taskDuration - idleStart.taskDuration) / (idleMs / 1000);
  const result = { label, heapGrowth, heapSlope, backingGrowth, backingSlope, domGrowth, idleCpuRatio };

  expect(heapGrowth, `${label}: JS heap growth`).toBeLessThanOrEqual(profile.maxHeapGrowthBytes);
  expect(heapSlope, `${label}: JS heap slope`).toBeLessThanOrEqual(profile.maxHeapSlopeBytesPerBatch);
  expect(backingGrowth, `${label}: backing/WASM growth`).toBeLessThanOrEqual(profile.maxBackingGrowthBytes);
  expect(backingSlope, `${label}: backing/WASM slope`).toBeLessThanOrEqual(profile.maxBackingSlopeBytesPerBatch);
  expect(domGrowth, `${label}: DOM/listener growth`).toBeLessThanOrEqual(profile.maxDomGrowth);
  expect(idleCpuRatio, `${label}: post-workload idle CPU`).toBeLessThanOrEqual(profile.maxIdleCpuRatio);
  console.log(`[resource] ${JSON.stringify(result)}`);
  return result;
}
