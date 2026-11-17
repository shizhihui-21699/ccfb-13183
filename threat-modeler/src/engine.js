import { THREAT_LIBRARY } from './threatLibrary.js';

// 简单稳定哈希(djb2),用于给威胁的"上下文"做指纹
export function hash(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) + h + str.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}

export function centerOf(el) {
  return { x: el.x + el.w / 2, y: el.y + el.h / 2 };
}

// 元素所属的信任边界:几何中心落在边界矩形内;嵌套时取面积最小者
export function boundaryOf(model, el) {
  if (!el || el.type === 'boundary') return null;
  const c = centerOf(el);
  let best = null;
  for (const b of Object.values(model.elements)) {
    if (b.type !== 'boundary') continue;
    if (c.x >= b.x && c.x <= b.x + b.w && c.y >= b.y && c.y <= b.y + b.h) {
      if (!best || b.w * b.h < best.w * best.h) best = b;
    }
  }
  return best;
}

export function flowCrossesBoundary(model, flow) {
  const src = model.elements[flow.source];
  const tgt = model.elements[flow.target];
  if (!src || !tgt) return false;
  const b1 = boundaryOf(model, src);
  const b2 = boundaryOf(model, tgt);
  return (b1?.id ?? null) !== (b2?.id ?? null);
}

function fill(tpl, name) {
  return tpl.replaceAll('{name}', name || '(未命名)');
}

// 由当前图推导出的威胁实例(不含用户填写的缓解/负责人)
export function computeThreatInstances(model) {
  const out = [];
  for (const el of Object.values(model.elements)) {
    if (el.type === 'boundary') continue;
    const boundary = boundaryOf(model, el);
    for (const lib of THREAT_LIBRARY) {
      if (lib.appliesTo.kind !== 'element') continue;
      if (!lib.appliesTo.types.includes(el.type)) continue;
      // 上下文指纹:名称、类型、所属边界变化都算"受影响"
      const contextHash = hash(JSON.stringify(['el', el.name, el.type, boundary?.id ?? null]));
      out.push({
        key: `el:${el.id}:${lib.id}`,
        libId: lib.id,
        stride: lib.stride,
        severity: lib.severity,
        title: fill(lib.title, el.name),
        description: fill(lib.description, el.name),
        suggested: lib.mitigation,
        targetKind: 'element',
        targetId: el.id,
        targetName: el.name,
        contextHash,
      });
    }
  }
  for (const flow of Object.values(model.flows)) {
    const src = model.elements[flow.source];
    const tgt = model.elements[flow.target];
    if (!src || !tgt) continue;
    const crosses = flowCrossesBoundary(model, flow);
    const label = flow.name || `${src.name} → ${tgt.name}`;
    for (const lib of THREAT_LIBRARY) {
      if (lib.appliesTo.kind !== 'flow') continue;
      if (lib.appliesTo.crossBoundaryOnly && !crosses) continue;
      // 上下文指纹:流名称、两端元素、是否跨边界
      const contextHash = hash(
        JSON.stringify(['fl', flow.name, src.id, src.name, tgt.id, tgt.name, crosses])
      );
      out.push({
        key: `fl:${flow.id}:${lib.id}`,
        libId: lib.id,
        stride: lib.stride,
        severity: lib.severity,
        title: fill(lib.title, label),
        description: fill(lib.description, label),
        suggested: lib.mitigation,
        targetKind: 'flow',
        targetId: flow.id,
        targetName: label,
        crossBoundary: crosses,
        contextHash,
      });
    }
  }
  return out;
}

// 把推导出的实例与已有威胁记录合并:
// - 新出现的 → 状态"待处理"
// - 上下文指纹变了 → 保留缓解措施/负责人,状态置为"待复核"
// - 对象被删除 → 标记 orphaned,状态置为"待复核",由人决定删除
export function reconcileThreats(model) {
  const instances = computeThreatInstances(model);
  const seen = new Set(instances.map((i) => i.key));
  const threats = {};
  for (const inst of instances) {
    const prev = model.threats[inst.key];
    if (!prev) {
      threats[inst.key] = { ...inst, status: 'open', mitigation: '', owner: '', orphaned: false };
    } else if (prev.contextHash !== inst.contextHash) {
      threats[inst.key] = {
        ...inst,
        mitigation: prev.mitigation,
        owner: prev.owner,
        status: 'needs-review',
        orphaned: false,
      };
    } else {
      threats[inst.key] = { ...inst, mitigation: prev.mitigation, owner: prev.owner, status: prev.status, orphaned: false };
    }
  }
  for (const [key, t] of Object.entries(model.threats)) {
    if (!seen.has(key) && !threats[key]) {
      threats[key] = { ...t, orphaned: true, status: 'needs-review' };
    }
  }
  return threats;
}

export const THREAT_STATUS = {
  'open': { name: '待处理', color: '#b91c1c' },
  'needs-review': { name: '待复核', color: '#b45309' },
  'mitigated': { name: '已缓解', color: '#15803d' },
  'accepted': { name: '已接受', color: '#64748b' },
};
