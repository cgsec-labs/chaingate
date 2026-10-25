// size-jump -- a CONTRIBUTING row in cft-policy-1.2 (contributing at >= 2x). The
// candidate's dist.unpackedSize against its predecessor (gates/predecessor.js). The runner's role table records a WARN from
// this gate as NOTE: shown beside a named row and as detail, never a warning on its own.
import { predecessorOf, MAX_WALK } from './predecessor.js';

export const RATIO = 2;
const GATE = 'size-jump';
const result = (r, detail) => ({ gate: GATE, result: r, detail });
const sizeOf = (m) => (m && typeof m === 'object' && m.dist && typeof m.dist === 'object'
  && typeof m.dist.unpackedSize === 'number' && Number.isFinite(m.dist.unpackedSize) && m.dist.unpackedSize > 0 ? m.dist.unpackedSize : null);

export default {
  name: GATE,
  evaluate(input) {
    const versions = input?.rawVersions;
    const size = sizeOf(versions?.[input?.version]);
    if (size === null) return result('SKIP', 'not evaluable: no dist.unpackedSize for this version');
    const pred = predecessorOf(versions, input?.rawTimes, input?.version, (m) => sizeOf(m) !== null);
    if (pred?.beyond) return result('SKIP', `not evaluable: no predecessor within the last ${MAX_WALK} lower releases`);
    if (!pred) return result('SKIP', 'not evaluable: no earlier release of this major with a size');
    const ratio = size / sizeOf(pred.manifest);
    const text = `unpackedSize ${size} vs ${sizeOf(pred.manifest)} of ${pred.version} (${ratio.toFixed(1)}×)`;
    return ratio >= RATIO ? result('WARN', `${text}, at or above ${RATIO}×`) : result('ALLOW', text);
  },
};
