// 威胁库:分类口径与初始条目
//
// 分类口径(与团队对齐的约定):
// 1. 一级分类采用 STRIDE 六类(微软威胁建模标准):
//    S 欺骗 / T 篡改 / R 抵赖 / I 信息泄露 / D 拒绝服务 / E 权限提升
// 2. 每个条目绑定适用对象:元素类型(外部实体/处理过程/数据存储/数据流),
//    适用关系遵循微软 DFD×STRIDE 经典映射:
//      外部实体 → S, R
//      处理过程 → S, T, R, I, D, E(全量)
//      数据存储 → T, R, I, D
//      数据流   → T, I, D
// 3. 跨信任边界的数据流额外叠加一组"边界条目"(crossBoundaryOnly),
//    因为跨越信任域是攻击面显著放大的位置,需要单独评审。
// 4. 严重度为默认建议值(高/中/低),评审时可在具体威胁上调整结论,
//    但分类口径不在单个模型里修改——要改就改本文件,保证跨系统可比。

export const STRIDE = {
  S: { name: '欺骗', en: 'Spoofing', color: '#b45309' },
  T: { name: '篡改', en: 'Tampering', color: '#b91c1c' },
  R: { name: '抵赖', en: 'Repudiation', color: '#6d28d9' },
  I: { name: '信息泄露', en: 'Information Disclosure', color: '#1d4ed8' },
  D: { name: '拒绝服务', en: 'Denial of Service', color: '#0f766e' },
  E: { name: '权限提升', en: 'Elevation of Privilege', color: '#be185d' },
};

export const ELEMENT_TYPES = {
  entity: { name: '外部实体' },
  process: { name: '处理过程' },
  store: { name: '数据存储' },
  boundary: { name: '信任边界' },
};

// appliesTo:
//   { kind: 'element', types: [...] }        — 挂在某类元素上
//   { kind: 'flow' }                          — 挂在所有数据流上
//   { kind: 'flow', crossBoundaryOnly: true } — 仅跨信任边界的数据流
// title/description 中的 {name} 会被替换为对象名称。
export const THREAT_LIBRARY = [
  // ---- 外部实体 ----
  {
    id: 'ent-spoof', stride: 'S', severity: '高',
    appliesTo: { kind: 'element', types: ['entity'] },
    title: '外部实体身份被伪造',
    description: '攻击者冒充「{name}」与系统交互,骗取信任后执行未授权操作。',
    mitigation: '对外部实体做强认证(MFA、客户端证书、双向 TLS),凭证统一管理与轮换。',
  },
  {
    id: 'ent-repud', stride: 'R', severity: '中',
    appliesTo: { kind: 'element', types: ['entity'] },
    title: '外部实体抵赖其操作',
    description: '「{name}」事后否认发起过的请求或交易,系统无法举证。',
    mitigation: '关键操作记录不可篡改的审计日志,重要交互使用数字签名或带签名的凭证。',
  },

  // ---- 处理过程 ----
  {
    id: 'proc-spoof', stride: 'S', severity: '高',
    appliesTo: { kind: 'element', types: ['process'] },
    title: '处理过程身份被冒用',
    description: '攻击者冒充「{name}」接收或响应请求,劫持上下游的信任关系。',
    mitigation: '服务间启用双向认证(mTLS、服务身份如 SPIFFE/SPIRE),杜绝仅凭网络位置信任。',
  },
  {
    id: 'proc-tamper', stride: 'T', severity: '高',
    appliesTo: { kind: 'element', types: ['process'] },
    title: '处理过程被篡改',
    description: '「{name}」的代码、配置或运行时被篡改,改变处理逻辑或植入恶意行为。',
    mitigation: '制品签名与完整性校验、最小权限运行、只读文件系统、变更走发布流水线。',
  },
  {
    id: 'proc-repud', stride: 'R', severity: '中',
    appliesTo: { kind: 'element', types: ['process'] },
    title: '处理过程操作不可追溯',
    description: '「{name}」执行的关键操作缺乏审计,出问题后无法定位责任与影响面。',
    mitigation: '集中式审计日志,记录操作主体、时间、对象与结果,日志异地留存。',
  },
  {
    id: 'proc-info', stride: 'I', severity: '高',
    appliesTo: { kind: 'element', types: ['process'] },
    title: '处理过程泄露敏感信息',
    description: '「{name}」通过日志、错误信息、调试接口或内存转储泄露敏感数据。',
    mitigation: '日志脱敏、生产环境关闭详细错误回显、限制调试端点、敏感数据最小化持有。',
  },
  {
    id: 'proc-dos', stride: 'D', severity: '中',
    appliesTo: { kind: 'element', types: ['process'] },
    title: '处理过程被拒绝服务',
    description: '「{name}」被耗尽 CPU/内存/连接等资源,无法为正常请求服务。',
    mitigation: '限流与配额、请求超时、熔断降级、资源隔离与自动扩容。',
  },
  {
    id: 'proc-eop', stride: 'E', severity: '高',
    appliesTo: { kind: 'element', types: ['process'] },
    title: '处理过程被利用提升权限',
    description: '攻击者通过「{name}」的漏洞(注入、反序列化、越权校验缺失)获得更高权限。',
    mitigation: '输入校验与参数化、最小权限原则、沙箱隔离、依赖与系统及时补丁。',
  },

  // ---- 数据存储 ----
  {
    id: 'store-tamper', stride: 'T', severity: '高',
    appliesTo: { kind: 'element', types: ['store'] },
    title: '数据存储被未授权修改',
    description: '「{name}」中的数据被直接篡改,破坏完整性且可能长期未被发现。',
    mitigation: '细粒度访问控制、写操作审计、完整性校验(哈希/签名)、定期备份比对。',
  },
  {
    id: 'store-repud', stride: 'R', severity: '中',
    appliesTo: { kind: 'element', types: ['store'] },
    title: '数据变更无法追溯',
    description: '对「{name}」的读写变更缺少记录,无法确认谁在何时改了什么。',
    mitigation: '开启数据库审计/变更日志,关键表保留历史版本。',
  },
  {
    id: 'store-info', stride: 'I', severity: '高',
    appliesTo: { kind: 'element', types: ['store'] },
    title: '数据存储被未授权读取',
    description: '「{name}」中的敏感数据被越权读取、拖库或通过备份/快照外泄。',
    mitigation: '静态加密、传输加密、最小权限账号、备份加密与访问审计、敏感字段脱敏。',
  },
  {
    id: 'store-dos', stride: 'D', severity: '中',
    appliesTo: { kind: 'element', types: ['store'] },
    title: '数据存储不可用',
    description: '「{name}」因攻击、故障或资源耗尽而不可用,阻断依赖它的业务。',
    mitigation: '主备/多副本、定期恢复演练、连接池与慢查询治理、容量监控。',
  },

  // ---- 数据流(所有流) ----
  {
    id: 'flow-tamper', stride: 'T', severity: '高',
    appliesTo: { kind: 'flow' },
    title: '传输中的数据被篡改',
    description: '数据流「{name}」在传输链路上被中间人修改,接收方拿到被污染的数据。',
    mitigation: '全程 TLS,关键报文加消息签名/MAC,接收方做完整性校验。',
  },
  {
    id: 'flow-info', stride: 'I', severity: '高',
    appliesTo: { kind: 'flow' },
    title: '传输中的数据被窃听',
    description: '数据流「{name}」以明文或弱加密传输,被嗅探后泄露内容。',
    mitigation: '强制 TLS(禁用弱协议与弱套件),敏感字段应用层二次加密。',
  },
  {
    id: 'flow-dos', stride: 'D', severity: '中',
    appliesTo: { kind: 'flow' },
    title: '数据流被中断或拥塞',
    description: '数据流「{name}」的链路被泛洪、切断或依赖的中间节点失效。',
    mitigation: '链路冗余、限流与防泛洪、超时重试与降级预案。',
  },

  // ---- 跨信任边界的数据流(叠加条目) ----
  {
    id: 'xflow-spoof', stride: 'S', severity: '高',
    appliesTo: { kind: 'flow', crossBoundaryOnly: true },
    title: '跨边界来源身份不可信',
    description: '数据流「{name}」跨越信任边界,对侧来源默认不可信,可能被伪造。',
    mitigation: '边界处强制认证对端身份(双向 TLS、签名令牌),不信任任何自声明身份。',
  },
  {
    id: 'xflow-tamper', stride: 'T', severity: '高',
    appliesTo: { kind: 'flow', crossBoundaryOnly: true },
    title: '跨边界传输经过不可信网络',
    description: '数据流「{name}」途经不可信网络,篡改与重放风险显著上升。',
    mitigation: '端到端加密与完整性保护,防重放(时间戳/Nonce/序号),必要时专用通道。',
  },
  {
    id: 'xflow-info', stride: 'I', severity: '高',
    appliesTo: { kind: 'flow', crossBoundaryOnly: true },
    title: '敏感数据流出信任域',
    description: '数据流「{name}」把数据带出了信任边界,暴露面扩大到不可控环境。',
    mitigation: '出域数据最小化与脱敏,评估接收方安全水位,必要时审批与加密留存。',
  },
  {
    id: 'xflow-eop', stride: 'E', severity: '高',
    appliesTo: { kind: 'flow', crossBoundaryOnly: true },
    title: '边界入口成为权限提升攻击面',
    description: '数据流「{name}」的接收端是高信任域的入口,是注入与越权攻击的首选目标。',
    mitigation: '入口做严格输入校验与鉴权,按零信任原则处理一切入域请求,定期渗透测试。',
  },
];
