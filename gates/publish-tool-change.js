// publish-tool-change -- a CONTRIBUTING row in cft-policy-1.2. Direction-aware:
// the candidate's _npmVersion LOWER than its predecessor's (gates/predecessor.js) is the signal (same-account abuse:
// npm@11.12.1 -> 9.2.0); an upgrade is not (migration to CI). Recorded as NOTE by the runner's role table.
import semver from 'semver';
import { predecessorOf, MAX_WALK } from './predecessor.js';

const GATE = 'publish-tool-change';
const result = (r, detail) => ({ gate: GATE, result: r, detail });
const toolOf = (m) => (m && typeof m === 'object' && typeof m._npmVersion === 'string' && semver.valid(m._npmVersion) ? m._npmVersion : null);

export default {
  name: GATE,
  evaluate(input) {
    const versions = input?.rawVersions;
    const tool = toolOf(versions?.[input?.version]);
    if (tool === null) return result('SKIP', 'not evaluable: no valid _npmVersion for this version');
    const pred = predecessorOf(versions, input?.rawTimes, input?.version, (m) => toolOf(m) !== null);
    if (pred?.beyond) return result('SKIP', `not evaluable: no predecessor within the last ${MAX_WALK} lower releases`);
    if (!pred) return result('SKIP', 'not evaluable: no earlier release of this major with a publishing tool');
    const before = toolOf(pred.manifest);
    return semver.lt(tool, before)
      ? result('WARN', `published with npm ${before} → ${tool} (a downgrade from ${pred.version})`)
      : result('ALLOW', `npm ${before} → ${tool}`);
  },
};
