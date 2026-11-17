import { ELEMENT_TYPES } from '../threatLibrary.js';
import { boundaryOf, flowCrossesBoundary } from '../engine.js';

export default function Properties({ model, dispatch, selection, setSelection }) {
  if (!selection) {
    return (
      <div className="panel-body muted">
        <p>未选中任何对象。</p>
        <p>左侧选择元素类型后在画布上点击放置;选择「数据流」后依次点击两个元素连线。</p>
      </div>
    );
  }

  if (selection.kind === 'element') {
    const el = model.elements[selection.id];
    if (!el) return null;
    const boundary = boundaryOf(model, el);
    return (
      <div className="panel-body">
        <div className="field">
          <label>类型</label>
          <div>{ELEMENT_TYPES[el.type].name}</div>
        </div>
        <div className="field">
          <label>名称</label>
          <input
            value={el.name}
            onChange={(e) => dispatch({ type: 'updateElement', id: el.id, patch: { name: e.target.value } })}
          />
        </div>
        {el.type !== 'boundary' && (
          <div className="field">
            <label>所属信任边界</label>
            <div>{boundary ? boundary.name : '—(边界外)'}</div>
          </div>
        )}
        <div className="field">
          <label>描述</label>
          <textarea
            rows={4}
            value={el.description}
            onChange={(e) => dispatch({ type: 'updateElement', id: el.id, patch: { description: e.target.value } })}
          />
        </div>
        <button
          className="danger"
          onClick={() => {
            dispatch({ type: 'removeElement', id: el.id });
            setSelection(null);
          }}
        >
          删除该{ELEMENT_TYPES[el.type].name}
        </button>
      </div>
    );
  }

  const flow = model.flows[selection.id];
  if (!flow) return null;
  const src = model.elements[flow.source];
  const tgt = model.elements[flow.target];
  const crosses = flowCrossesBoundary(model, flow);
  return (
    <div className="panel-body">
      <div className="field">
        <label>数据流</label>
        <div>
          {src?.name} → {tgt?.name}
        </div>
      </div>
      <div className="field">
        <label>名称 / 协议</label>
        <input
          value={flow.name}
          placeholder="如 HTTPS、SQL、消息队列"
          onChange={(e) => dispatch({ type: 'updateFlow', id: flow.id, patch: { name: e.target.value } })}
        />
      </div>
      <div className="field">
        <label>跨信任边界</label>
        <div className={crosses ? 'cross-yes' : ''}>{crosses ? '是(已叠加边界威胁)' : '否'}</div>
      </div>
      <div className="field">
        <label>描述</label>
        <textarea
          rows={4}
          value={flow.description}
          onChange={(e) => dispatch({ type: 'updateFlow', id: flow.id, patch: { description: e.target.value } })}
        />
      </div>
      <button
        className="danger"
        onClick={() => {
          dispatch({ type: 'removeFlow', id: flow.id });
          setSelection(null);
        }}
      >
        删除该数据流
      </button>
    </div>
  );
}
