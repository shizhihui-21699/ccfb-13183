import { useRef, useState } from 'react';
import { centerOf, boundaryOf, flowCrossesBoundary } from '../engine.js';

// 从元素边缘指向 target 方向的出射点(用于让箭头停在形状边缘)
function edgePoint(el, towards) {
  const c = centerOf(el);
  const dx = towards.x - c.x;
  const dy = towards.y - c.y;
  if (dx === 0 && dy === 0) return c;
  if (el.type === 'process') {
    // 椭圆
    const rx = el.w / 2;
    const ry = el.h / 2;
    const t = 1 / Math.sqrt((dx * dx) / (rx * rx) + (dy * dy) / (ry * ry));
    return { x: c.x + dx * t, y: c.y + dy * t };
  }
  // 矩形(实体/存储/边界)
  const rx = el.w / 2;
  const ry = el.h / 2;
  const t = Math.min(Math.abs(rx / (dx || 1e-9)), Math.abs(ry / (dy || 1e-9)));
  return { x: c.x + dx * t, y: c.y + dy * t };
}

function ElementShape({ el, selected, inBoundary }) {
  const common = {
    fill: 'var(--el-fill)',
    stroke: selected ? 'var(--accent)' : 'var(--el-stroke)',
    strokeWidth: selected ? 2.5 : 1.5,
  };
  switch (el.type) {
    case 'entity':
      return <rect x={el.x} y={el.y} width={el.w} height={el.h} rx={4} {...common} />;
    case 'process':
      return (
        <ellipse
          cx={el.x + el.w / 2}
          cy={el.y + el.h / 2}
          rx={el.w / 2}
          ry={el.h / 2}
          {...common}
        />
      );
    case 'store':
      return (
        <g>
          <line x1={el.x} y1={el.y} x2={el.x + el.w} y2={el.y} {...common} fill="none" />
          <line x1={el.x} y1={el.y + el.h} x2={el.x + el.w} y2={el.y + el.h} {...common} fill="none" />
          <rect
            x={el.x}
            y={el.y}
            width={el.w}
            height={el.h}
            fill="var(--el-fill)"
            stroke="none"
          />
          <line x1={el.x} y1={el.y} x2={el.x} y2={el.y + el.h} {...common} fill="none" />
        </g>
      );
    case 'boundary':
      return (
        <rect
          x={el.x}
          y={el.y}
          width={el.w}
          height={el.h}
          rx={8}
          fill={inBoundary ? 'var(--boundary-fill)' : 'var(--boundary-fill)'}
          stroke={selected ? 'var(--accent)' : 'var(--boundary-stroke)'}
          strokeWidth={selected ? 2.5 : 1.5}
          strokeDasharray="8 5"
        />
      );
    default:
      return null;
  }
}

export default function Canvas({ model, dispatch, mode, setMode, selection, setSelection }) {
  const svgRef = useRef(null);
  const [drag, setDrag] = useState(null);
  const [connectFrom, setConnectFrom] = useState(null);

  function toSvg(e) {
    const pt = svgRef.current.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    return pt.matrixTransform(svgRef.current.getScreenCTM().inverse());
  }

  function onBackgroundPointerDown(e) {
    if (mode.kind === 'place') {
      const p = toSvg(e);
      dispatch({ type: 'addElement', elementType: mode.elementType, x: p.x, y: p.y });
      return;
    }
    setSelection(null);
    setConnectFrom(null);
  }

  function onElementPointerDown(e, el) {
    e.stopPropagation();
    if (mode.kind === 'connect') {
      if (el.type === 'boundary') return;
      if (!connectFrom) {
        setConnectFrom(el.id);
      } else {
        dispatch({ type: 'addFlow', source: connectFrom, target: el.id });
        setConnectFrom(null);
      }
      return;
    }
    setSelection({ kind: 'element', id: el.id });
    const p = toSvg(e);
    setDrag({ kind: 'move', id: el.id, dx: p.x - el.x, dy: p.y - el.y });
    e.currentTarget.setPointerCapture?.(e.pointerId);
  }

  function onResizePointerDown(e, el) {
    e.stopPropagation();
    setSelection({ kind: 'element', id: el.id });
    setDrag({ kind: 'resize', id: el.id });
    e.currentTarget.setPointerCapture?.(e.pointerId);
  }

  function onPointerMove(e) {
    if (!drag) return;
    const p = toSvg(e);
    if (drag.kind === 'move') {
      dispatch({ type: 'moveElement', id: drag.id, x: p.x - drag.dx, y: p.y - drag.dy });
    } else if (drag.kind === 'resize') {
      const el = model.elements[drag.id];
      if (el) dispatch({ type: 'resizeElement', id: drag.id, w: p.x - el.x, h: p.y - el.y });
    }
  }

  function onPointerUp() {
    setDrag(null);
  }

  function onFlowClick(e, flow) {
    e.stopPropagation();
    setSelection({ kind: 'flow', id: flow.id });
  }

  const boundaries = Object.values(model.elements).filter((el) => el.type === 'boundary');
  const nodes = Object.values(model.elements).filter((el) => el.type !== 'boundary');
  const flows = Object.values(model.flows);

  return (
    <svg
      ref={svgRef}
      className={`canvas mode-${mode.kind}`}
      onPointerDown={onBackgroundPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
    >
      <defs>
        <marker
          id="arrow"
          viewBox="0 0 10 10"
          refX="9"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--flow-stroke)" />
        </marker>
        <marker
          id="arrow-cross"
          viewBox="0 0 10 10"
          refX="9"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--flow-cross)" />
        </marker>
      </defs>

      {/* 信任边界(最底层) */}
      {boundaries.map((el) => (
        <g
          key={el.id}
          onPointerDown={(e) => onElementPointerDown(e, el)}
          style={{ cursor: mode.kind === 'select' ? 'move' : 'default' }}
        >
          <ElementShape el={el} selected={selection?.id === el.id} />
          <text x={el.x + 10} y={el.y + 20} className="boundary-label">
            {el.name}
          </text>
          {selection?.id === el.id && (
            <circle
              cx={el.x + el.w}
              cy={el.y + el.h}
              r={7}
              className="resize-handle"
              onPointerDown={(e) => onResizePointerDown(e, el)}
            />
          )}
        </g>
      ))}

      {/* 数据流 */}
      {flows.map((f) => {
        const src = model.elements[f.source];
        const tgt = model.elements[f.target];
        if (!src || !tgt) return null;
        const crosses = flowCrossesBoundary(model, f);
        const p1 = edgePoint(src, centerOf(tgt));
        const p2 = edgePoint(tgt, centerOf(src));
        const mid = { x: (p1.x + p2.x) / 2, y: (p1.y + p2.y) / 2 };
        const selected = selection?.kind === 'flow' && selection.id === f.id;
        return (
          <g key={f.id} onPointerDown={(e) => onFlowClick(e, f)} style={{ cursor: 'pointer' }}>
            <line x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y} stroke="transparent" strokeWidth={14} />
            <line
              x1={p1.x}
              y1={p1.y}
              x2={p2.x}
              y2={p2.y}
              stroke={selected ? 'var(--accent)' : crosses ? 'var(--flow-cross)' : 'var(--flow-stroke)'}
              strokeWidth={selected ? 2.5 : 1.8}
              strokeDasharray={crosses ? '6 4' : undefined}
              markerEnd={`url(#${crosses ? 'arrow-cross' : 'arrow'})`}
            />
            {(f.name || crosses) && (
              <text x={mid.x} y={mid.y - 6} className="flow-label" textAnchor="middle">
                {f.name}
                {crosses && <tspan className="flow-cross-badge">{f.name ? ' · ' : ''}跨边界</tspan>}
              </text>
            )}
          </g>
        );
      })}

      {/* 元素 */}
      {nodes.map((el) => {
        const selected = selection?.kind === 'element' && selection.id === el.id;
        const isConnectSource = connectFrom === el.id;
        return (
          <g
            key={el.id}
            onPointerDown={(e) => onElementPointerDown(e, el)}
            style={{ cursor: mode.kind === 'select' ? 'move' : 'pointer' }}
          >
            <ElementShape el={el} selected={selected || isConnectSource} />
            <text
              x={el.x + el.w / 2}
              y={el.y + el.h / 2}
              className="el-label"
              textAnchor="middle"
              dominantBaseline="central"
            >
              {el.name}
            </text>
            {selected && el.type !== 'boundary' && (
              <circle
                cx={el.x + el.w}
                cy={el.y + el.h}
                r={6}
                className="resize-handle"
                onPointerDown={(e) => onResizePointerDown(e, el)}
              />
            )}
          </g>
        );
      })}

      {/* 连线模式提示 */}
      {mode.kind === 'connect' && connectFrom && model.elements[connectFrom] && (
        <text x={16} y={28} className="canvas-hint">
          已选起点「{model.elements[connectFrom].name}」,点击目标元素完成连线
        </text>
      )}
      {mode.kind === 'place' && (
        <text x={16} y={28} className="canvas-hint">
          点击画布放置「{mode.label}」,Esc 退出
        </text>
      )}
    </svg>
  );
}
