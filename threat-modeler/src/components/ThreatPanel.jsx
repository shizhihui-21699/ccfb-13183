import { useState } from 'react';
import { STRIDE } from '../threatLibrary.js';
import { THREAT_STATUS } from '../engine.js';

const STATUS_ORDER = ['needs-review', 'open', 'mitigated', 'accepted'];

function ThreatItem({ threat, dispatch }) {
  const [open, setOpen] = useState(threat.status === 'needs-review');
  const stride = STRIDE[threat.stride];
  const status = THREAT_STATUS[threat.status];

  return (
    <div className={`threat-item status-${threat.status}`}>
      <div className="threat-head" onClick={() => setOpen(!open)}>
        <span className="stride-chip" style={{ background: stride.color }}>
          {threat.stride}
        </span>
        <span className="threat-title">
          {threat.title}
          {threat.orphaned && <em className="orphan-tag">来源已删除</em>}
        </span>
        <span className="status-chip" style={{ color: status.color }}>
          {status.name}
        </span>
      </div>
      {open && (
        <div className="threat-detail">
          <p className="threat-desc">{threat.description}</p>
          <p className="threat-meta">
            对象:{threat.targetName} · 严重度:{threat.severity}
            {threat.crossBoundary && ' · 跨信任边界'}
          </p>
          <p className="threat-suggested">建议:{threat.suggested}</p>
          {threat.status === 'needs-review' && (
            <p className="review-hint">
              {threat.orphaned
                ? '该威胁的来源对象已从图中删除,请确认后移除记录。'
                : '模型已变更,该威胁的上下文发生变化,请复核后标记状态。'}
            </p>
          )}
          <label>缓解措施</label>
          <textarea
            rows={2}
            value={threat.mitigation}
            placeholder="记录已采取或计划采取的缓解措施"
            onChange={(e) => dispatch({ type: 'updateThreat', key: threat.key, patch: { mitigation: e.target.value } })}
          />
          <label>负责人</label>
          <input
            value={threat.owner}
            placeholder="负责人"
            onChange={(e) => dispatch({ type: 'updateThreat', key: threat.key, patch: { owner: e.target.value } })}
          />
          <div className="threat-actions">
            {Object.entries(THREAT_STATUS).map(([code, meta]) => (
              <button
                key={code}
                className={threat.status === code ? 'active' : ''}
                onClick={() => dispatch({ type: 'updateThreat', key: threat.key, patch: { status: code } })}
              >
                {meta.name}
              </button>
            ))}
            {threat.orphaned && (
              <button
                className="danger"
                onClick={() => dispatch({ type: 'dismissThreat', key: threat.key })}
              >
                移除记录
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ThreatPanel({ model, dispatch }) {
  const [filter, setFilter] = useState('all');
  const threats = Object.values(model.threats).sort((a, b) => {
    const d = STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status);
    return d !== 0 ? d : a.stride.localeCompare(b.stride);
  });
  const filtered = filter === 'all' ? threats : threats.filter((t) => t.status === filter);
  const counts = Object.fromEntries(
    Object.keys(THREAT_STATUS).map((s) => [s, threats.filter((t) => t.status === s).length])
  );

  return (
    <div className="panel-body">
      <div className="threat-filter">
        <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="all">全部({threats.length})</option>
          {Object.entries(THREAT_STATUS).map(([code, meta]) => (
            <option key={code} value={code}>
              {meta.name}({counts[code]})
            </option>
          ))}
        </select>
      </div>
      {filtered.length === 0 && <p className="muted">没有匹配的威胁。</p>}
      {filtered.map((t) => (
        <ThreatItem key={t.key} threat={t} dispatch={dispatch} />
      ))}
    </div>
  );
}
