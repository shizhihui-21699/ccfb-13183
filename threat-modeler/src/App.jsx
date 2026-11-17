import { useEffect, useReducer, useRef, useState } from 'react';
import Canvas from './components/Canvas.jsx';
import Properties from './components/Properties.jsx';
import ThreatPanel from './components/ThreatPanel.jsx';
import { reducer, loadInitialModel, STORAGE_KEY } from './model.js';
import { generateReport, downloadFile } from './report.js';

const PALETTE = [
  { kind: 'select', label: '选择/移动' },
  { kind: 'place', elementType: 'entity', label: '外部实体' },
  { kind: 'place', elementType: 'process', label: '处理过程' },
  { kind: 'place', elementType: 'store', label: '数据存储' },
  { kind: 'place', elementType: 'boundary', label: '信任边界' },
  { kind: 'connect', label: '数据流' },
];

export default function App() {
  const [model, dispatch] = useReducer(reducer, undefined, loadInitialModel);
  const [mode, setMode] = useState(PALETTE[0]);
  const [selection, setSelection] = useState(null);
  const [tab, setTab] = useState('threats');
  const fileRef = useRef(null);

  // 自动保存到 localStorage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(model));
    } catch {
      /* 存储不可用时忽略 */
    }
  }, [model]);

  // 快捷键:Delete 删除选中,Esc 回到选择模式
  useEffect(() => {
    function onKey(e) {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      if (e.key === 'Escape') {
        setMode(PALETTE[0]);
        setSelection(null);
      }
      if ((e.key === 'Delete' || e.key === 'Backspace') && selection) {
        if (selection.kind === 'element') dispatch({ type: 'removeElement', id: selection.id });
        if (selection.kind === 'flow') dispatch({ type: 'removeFlow', id: selection.id });
        setSelection(null);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selection]);

  const reviewCount = Object.values(model.threats).filter((t) => t.status === 'needs-review').length;

  function exportJson() {
    downloadFile(`${model.name}.threatmodel.json`, JSON.stringify(model, null, 2), 'application/json');
  }

  function importJson(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const m = JSON.parse(reader.result);
        if (!m.elements || !m.flows || !m.threats) throw new Error('bad shape');
        dispatch({ type: 'load', model: m });
        setSelection(null);
      } catch {
        window.alert('导入失败:文件不是有效的威胁模型 JSON。');
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  }

  return (
    <div className="app">
      <header className="topbar">
        <input
          className="model-name"
          value={model.name}
          onChange={(e) => dispatch({ type: 'setName', name: e.target.value })}
        />
        <span className="save-hint">已自动保存</span>
        <div className="topbar-actions">
          <button onClick={() => downloadFile(`${model.name}-威胁模型报告.md`, generateReport(model))}>
            导出报告
          </button>
          <button onClick={exportJson}>导出 JSON</button>
          <button onClick={() => fileRef.current?.click()}>导入 JSON</button>
          <button
            className="danger"
            onClick={() => {
              if (window.confirm('确定清空当前模型并新建?')) {
                dispatch({ type: 'reset' });
                setSelection(null);
              }
            }}
          >
            新建
          </button>
          <input ref={fileRef} type="file" accept=".json" hidden onChange={importJson} />
        </div>
      </header>

      <div className="main">
        <nav className="palette">
          {PALETTE.map((p) => (
            <button
              key={p.label}
              className={mode.label === p.label ? 'active' : ''}
              onClick={() => setMode(p)}
            >
              {p.label}
            </button>
          ))}
        </nav>

        <Canvas
          model={model}
          dispatch={dispatch}
          mode={mode}
          setMode={setMode}
          selection={selection}
          setSelection={setSelection}
        />

        <aside className="sidebar">
          <div className="tabs">
            <button className={tab === 'threats' ? 'active' : ''} onClick={() => setTab('threats')}>
              威胁{reviewCount > 0 && <span className="badge">{reviewCount} 待复核</span>}
            </button>
            <button className={tab === 'props' ? 'active' : ''} onClick={() => setTab('props')}>
              属性
            </button>
          </div>
          {tab === 'threats' ? (
            <ThreatPanel model={model} dispatch={dispatch} />
          ) : (
            <Properties
              model={model}
              dispatch={dispatch}
              selection={selection}
              setSelection={setSelection}
            />
          )}
        </aside>
      </div>
    </div>
  );
}
