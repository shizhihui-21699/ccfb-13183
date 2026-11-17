import { reconcileThreats } from './engine.js';

let counter = 0;
export function uid(prefix) {
  counter += 1;
  return `${prefix}-${Date.now().toString(36)}-${counter}`;
}

const DEFAULT_SIZES = {
  entity: { w: 130, h: 64 },
  process: { w: 150, h: 84 },
  store: { w: 150, h: 64 },
  boundary: { w: 340, h: 240 },
};

const DEFAULT_NAMES = {
  entity: '外部实体',
  process: '处理过程',
  store: '数据存储',
  boundary: '信任边界',
};

// 首次打开时的示例模型,演示跨边界流自动出威胁
function seedModel() {
  const el = (id, type, name, x, y, w, h, description = '') => ({
    id, type, name, x, y, w, h, description,
  });
  const elements = {
    b1: el('b1', 'boundary', '内网信任区', 500, 110, 480, 220, '办公网/生产网内部,默认可信'),
    user: el('user', 'entity', '用户', 60, 190, 130, 64, '浏览器访问者'),
    web: el('web', 'process', 'Web 前端', 280, 180, 150, 84, '静态页面 + BFF'),
    api: el('api', 'process', '订单 API', 580, 170, 150, 84, '订单核心服务'),
    db: el('db', 'store', '订单数据库', 800, 180, 150, 64, 'MySQL 主从'),
    pay: el('pay', 'entity', '支付网关', 580, 420, 130, 64, '第三方支付'),
  };
  const flows = {
    f1: { id: 'f1', name: 'HTTPS 请求', source: 'user', target: 'web', description: '' },
    f2: { id: 'f2', name: 'REST/JSON', source: 'web', target: 'api', description: '' },
    f3: { id: 'f3', name: 'SQL', source: 'api', target: 'db', description: '' },
    f4: { id: 'f4', name: '支付回调', source: 'pay', target: 'api', description: '' },
  };
  const model = { name: '示例:在线订单系统', elements, flows, threats: {} };
  model.threats = reconcileThreats(model);
  return model;
}

export function loadInitialModel() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const m = JSON.parse(raw);
      if (m && m.elements && m.flows && m.threats) return m;
    }
  } catch {
    /* 本地数据损坏时回退到示例 */
  }
  return seedModel();
}

export const STORAGE_KEY = 'threat-modeler:model:v1';

// 图结构变化后需要重新对账威胁
function withReconcile(model) {
  return { ...model, threats: reconcileThreats(model) };
}

export function reducer(model, action) {
  switch (action.type) {
    case 'setName':
      return { ...model, name: action.name };

    case 'addElement': {
      const id = uid('el');
      const size = DEFAULT_SIZES[action.elementType];
      const el = {
        id,
        type: action.elementType,
        name: DEFAULT_NAMES[action.elementType],
        x: Math.round(action.x - size.w / 2),
        y: Math.round(action.y - size.h / 2),
        w: size.w,
        h: size.h,
        description: '',
      };
      return withReconcile({ ...model, elements: { ...model.elements, [id]: el } });
    }

    case 'moveElement': {
      const el = model.elements[action.id];
      if (!el) return model;
      const next = {
        ...model,
        elements: {
          ...model.elements,
          [action.id]: { ...el, x: Math.round(action.x), y: Math.round(action.y) },
        },
      };
      return withReconcile(next);
    }

    case 'resizeElement': {
      const el = model.elements[action.id];
      if (!el) return model;
      const next = {
        ...model,
        elements: {
          ...model.elements,
          [action.id]: {
            ...el,
            w: Math.max(80, Math.round(action.w)),
            h: Math.max(48, Math.round(action.h)),
          },
        },
      };
      return withReconcile(next);
    }

    case 'updateElement': {
      const el = model.elements[action.id];
      if (!el) return model;
      const next = {
        ...model,
        elements: { ...model.elements, [action.id]: { ...el, ...action.patch } },
      };
      return withReconcile(next);
    }

    case 'removeElement': {
      const elements = { ...model.elements };
      delete elements[action.id];
      const flows = Object.fromEntries(
        Object.entries(model.flows).filter(
          ([, f]) => f.source !== action.id && f.target !== action.id
        )
      );
      return withReconcile({ ...model, elements, flows });
    }

    case 'addFlow': {
      if (action.source === action.target) return model;
      const dup = Object.values(model.flows).some(
        (f) => f.source === action.source && f.target === action.target
      );
      if (dup) return model;
      const id = uid('fl');
      const flow = { id, name: '', source: action.source, target: action.target, description: '' };
      return withReconcile({ ...model, flows: { ...model.flows, [id]: flow } });
    }

    case 'updateFlow': {
      const flow = model.flows[action.id];
      if (!flow) return model;
      const next = { ...model, flows: { ...model.flows, [action.id]: { ...flow, ...action.patch } } };
      return withReconcile(next);
    }

    case 'removeFlow': {
      const flows = { ...model.flows };
      delete flows[action.id];
      return withReconcile({ ...model, flows });
    }

    case 'updateThreat': {
      const t = model.threats[action.key];
      if (!t) return model;
      return {
        ...model,
        threats: { ...model.threats, [action.key]: { ...t, ...action.patch } },
      };
    }

    case 'dismissThreat': {
      const threats = { ...model.threats };
      delete threats[action.key];
      return { ...model, threats };
    }

    case 'load':
      return action.model;

    case 'reset':
      return { name: '未命名威胁模型', elements: {}, flows: {}, threats: {} };

    default:
      return model;
  }
}
