import { STRIDE, ELEMENT_TYPES } from './threatLibrary.js';
import { THREAT_STATUS, boundaryOf, flowCrossesBoundary } from './engine.js';

function esc(s) {
  return String(s ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
}

export function generateReport(model) {
  const lines = [];
  const elements = Object.values(model.elements);
  const flows = Object.values(model.flows);
  const threats = Object.values(model.threats);
  const now = new Date().toLocaleString('zh-CN');

  lines.push(`# 威胁模型报告:${model.name}`);
  lines.push('');
  lines.push(`- 生成时间:${now}`);
  lines.push(`- 元素数量:${elements.filter((e) => e.type !== 'boundary').length}(信任边界 ${elements.filter((e) => e.type === 'boundary').length} 个)`);
  lines.push(`- 数据流数量:${flows.length}(跨信任边界 ${flows.filter((f) => flowCrossesBoundary(model, f)).length} 条)`);
  lines.push(`- 威胁总数:${threats.length}`);
  for (const [status, meta] of Object.entries(THREAT_STATUS)) {
    const n = threats.filter((t) => t.status === status).length;
    if (n) lines.push(`  - ${meta.name}:${n}`);
  }
  lines.push('');

  lines.push('## 元素清单');
  lines.push('');
  lines.push('| 类型 | 名称 | 所属信任边界 | 描述 |');
  lines.push('| --- | --- | --- | --- |');
  for (const el of elements) {
    if (el.type === 'boundary') continue;
    const b = boundaryOf(model, el);
    lines.push(`| ${ELEMENT_TYPES[el.type].name} | ${esc(el.name)} | ${esc(b?.name ?? '—')} | ${esc(el.description)} |`);
  }
  lines.push('');

  if (elements.some((e) => e.type === 'boundary')) {
    lines.push('## 信任边界');
    lines.push('');
    lines.push('| 名称 | 描述 |');
    lines.push('| --- | --- |');
    for (const el of elements) {
      if (el.type !== 'boundary') continue;
      lines.push(`| ${esc(el.name)} | ${esc(el.description)} |`);
    }
    lines.push('');
  }

  lines.push('## 数据流');
  lines.push('');
  lines.push('| 名称 | 来源 | 目标 | 跨信任边界 | 描述 |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const f of flows) {
    const src = model.elements[f.source];
    const tgt = model.elements[f.target];
    lines.push(
      `| ${esc(f.name || '(未命名)')} | ${esc(src?.name ?? '?')} | ${esc(tgt?.name ?? '?')} | ${flowCrossesBoundary(model, f) ? '是' : '否'} | ${esc(f.description)} |`
    );
  }
  lines.push('');

  lines.push('## 威胁清单(按 STRIDE 分类)');
  lines.push('');
  for (const [code, meta] of Object.entries(STRIDE)) {
    const group = threats.filter((t) => t.stride === code);
    if (!group.length) continue;
    lines.push(`### ${code} - ${meta.name}(${meta.en})`);
    lines.push('');
    lines.push('| 威胁 | 对象 | 严重度 | 状态 | 负责人 | 缓解措施 |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const t of group) {
      const statusName = THREAT_STATUS[t.status]?.name ?? t.status;
      const orphan = t.orphaned ? '(来源已删除)' : '';
      lines.push(
        `| ${esc(t.title)}${orphan} | ${esc(t.targetName)} | ${t.severity} | ${statusName} | ${esc(t.owner)} | ${esc(t.mitigation)} |`
      );
    }
    lines.push('');
  }

  const review = threats.filter((t) => t.status === 'needs-review');
  if (review.length) {
    lines.push('## 待复核威胁');
    lines.push('');
    lines.push('以下威胁因模型变更或来源对象被删除而需要人工复核:');
    lines.push('');
    for (const t of review) {
      lines.push(`- **${t.title}**(对象:${t.targetName}${t.orphaned ? ',来源已删除' : ''})`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('*本报告由威胁建模工具自动生成。*');
  return lines.join('\n');
}

export function downloadFile(filename, content, mime = 'text/markdown') {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
