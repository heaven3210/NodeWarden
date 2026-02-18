#!/usr/bin/env npx tsx
/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  NodeWarden 自查程序 — Bitwarden API 兼容性全面诊断         ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * 功能：自动验证 NodeWarden 服务端的所有 API 端点，确保兼容
 *       Bitwarden 全平台客户端（Windows / Android / iOS / 浏览器
 *       插件 / Linux / macOS / CLI）。
 *
 * 核心特性：
 *   · 内置 Bitwarden 标准 KDF（PBKDF2-SHA256），输入明文密码即可
 *   · 自动注册（全新实例）或自动登录（已有用户）
 *   · 空保管库锁定/解锁回归测试（历史 bug 场景）
 *   · JWT 内部声明验证（移动端依赖）
 *   · 多客户端平台兼容性验证（不同 client_id、设备头）
 *   · CORS 深度验证（浏览器插件依赖）
 *   · 覆盖全部已实现端点 + 未实现端点差距分析
 *   · 响应结构合规性校验（字段、格式、嵌套结构）
 *   · 带颜色的分组输出 + 汇总报告
 *
 * 用法：
 *   npx tsx tests/selfcheck.ts [服务器地址] [邮箱] [明文密码]
 *
 * 示例：
 *   npx tsx tests/selfcheck.ts http://localhost:8787 test@test.com testtesttest
 *
 * 也可以通过环境变量传入（优先级低于命令行参数）：
 *   NW_URL=http://localhost:8787
 *   NW_EMAIL=test@test.com
 *   NW_PASSWORD=testtesttest
 *
 * 注意：
 *   · 运行前请确保 NodeWarden 服务器已启动（npm run dev）
 *   · 自查会创建测试数据（文件夹、密码项等），测试结束后会自动清理
 *   · 如果是全新数据库，会自动用提供的邮箱和密码注册第一个用户
 */

import { pbkdf2Sync, randomBytes } from 'node:crypto';

// ─── 配置 ───────────────────────────────────────────────────────────────────
// 优先取命令行参数，其次取环境变量，最后用默认值

const BASE     = (process.argv[2] || process.env.NW_URL      || 'https://key.shuai.plus').replace(/\/+$/, '');
const EMAIL    = (process.argv[3] || process.env.NW_EMAIL    || 'shuai@cock.li').toLowerCase();
const PASSWORD = (process.argv[4] || process.env.NW_PASSWORD || 'rezwangul4qoxka@');

// ─── Bitwarden KDF ─────────────────────────────────────────────────────────
// Bitwarden 客户端在注册和登录时，不会把明文密码发给服务器。
// 流程：
//   1. prelogin 获取 KDF 参数（kdfType, kdfIterations）
//   2. masterKey = PBKDF2-SHA256(password, salt=email, iterations, 32字节)
//   3. masterPasswordHash = Base64( PBKDF2-SHA256(masterKey, salt=password, 1次, 32字节) )
//   4. 把 masterPasswordHash 发给服务器
//
// 下面的函数实现了这套标准流程。

/**
 * 计算 Bitwarden 的 masterPasswordHash
 * @param password   - 用户明文密码
 * @param email      - 用户邮箱（小写，作为盐）
 * @param kdfType    - KDF 类型（0=PBKDF2, 1=Argon2id）
 * @param iterations - KDF 迭代次数
 * @returns Base64 编码的 masterPasswordHash
 */
function computePasswordHash(password: string, email: string, kdfType: number, iterations: number): string {
  if (kdfType !== 0) {
    throw new Error(`不支持的 KDF 类型: ${kdfType}（仅支持 PBKDF2=0）`);
  }
  // 第一步：用邮箱作为盐，对密码做 PBKDF2 派生 → masterKey（32字节）
  const masterKey = pbkdf2Sync(password, email, iterations, 32, 'sha256');
  // 第二步：用密码作为盐，对 masterKey 再做 1 次 PBKDF2 → 最终哈希
  const hash = pbkdf2Sync(masterKey, password, 1, 32, 'sha256');
  return hash.toString('base64');
}

/**
 * 生成假的加密密钥（注册时占位用）
 * 格式模拟 Bitwarden 客户端: "2.base64IV|base64Data|base64MAC"
 */
function generateFakeEncKey(): string {
  const iv   = randomBytes(16).toString('base64');
  const data = randomBytes(32).toString('base64');
  const mac  = randomBytes(32).toString('base64');
  return `2.${iv}|${data}|${mac}`;
}

/**
 * 解码 JWT payload（不验证签名，仅用于检查声明字段）
 * Bitwarden 移动端会在本地解码 JWT 检查 email_verified、amr 等字段
 */
function decodeJwtPayload(token: string): Record<string, any> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    // JWT 的 base64url 编码需要转换为标准 base64
    let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return JSON.parse(Buffer.from(b64, 'base64').toString('utf-8'));
  } catch { return null; }
}

// ─── ANSI 颜色 ─────────────────────────────────────────────────────────────

const c = {
  reset : '\x1b[0m',
  bold  : '\x1b[1m',
  dim   : '\x1b[2m',
  green : '\x1b[32m',
  red   : '\x1b[31m',
  yellow: '\x1b[33m',
  cyan  : '\x1b[36m',
  gray  : '\x1b[90m',
  white : '\x1b[97m',
};

// ─── 结果类型 ───────────────────────────────────────────────────────────────

type Status = 'PASS' | 'FAIL' | 'WARN' | 'SKIP';

interface TestResult {
  group   : string;
  name    : string;
  status  : Status;
  detail? : string;
  ms      : number;
}

// ─── 运行时状态 ─────────────────────────────────────────────────────────────

let masterPasswordHash = '';  // 经 KDF 计算后的密码哈希
let userEncKey         = '';  // 用户加密密钥
let accessToken        = '';  // JWT 访问令牌
let refreshToken       = '';  // 刷新令牌
let userId             = '';  // 用户 ID
let testFolderId       = '';  // 测试文件夹 ID
let testCipherId       = '';  // 测试 Login 密码项 ID
let testCipher2Id      = '';  // 测试 SecureNote 密码项 ID（将被永久删除）
let testAttachmentId   = '';  // 测试附件 ID
let downloadToken      = '';  // 附件下载令牌
let isNewRegistration  = false;

// Track ALL test-created cipher and folder IDs so cleanup can permanently delete them.
// This prevents leftover undecryptable "[error: cannot decrypt]" items in the vault.
const allCreatedCipherIds: string[] = [];
const allCreatedFolderIds: string[] = [];

const results: TestResult[] = [];

// ─── HTTP 请求辅助 ─────────────────────────────────────────────────────────

type FetchOpt = {
  method?  : string;
  body?    : any;
  form?    : Record<string, string>;
  auth?    : boolean;
  headers? : Record<string, string>;
};

/**
 * 统一 API 请求封装
 * @param path - 请求路径
 * @param opt  - 选项：method、body（JSON）、form（表单）、auth（是否附加令牌）、headers
 */
async function api(path: string, opt: FetchOpt = {}): Promise<{ status: number; body: any; raw: Response }> {
  const url = `${BASE}${path}`;
  const headers: Record<string, string> = { 'Accept': 'application/json', ...opt.headers };

  if (opt.auth !== false && accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  let reqBody: string | undefined;
  if (opt.form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    reqBody = new URLSearchParams(opt.form).toString();
  } else if (opt.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    reqBody = JSON.stringify(opt.body);
  }

  const resp = await fetch(url, { method: opt.method || 'GET', headers, body: reqBody, redirect: 'manual' });
  let body: any;
  const text = await resp.text();
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: resp.status, body, raw: resp };
}

// ─── 测试运行器 ─────────────────────────────────────────────────────────────

let currentGroup = '';

function group(name: string) {
  currentGroup = name;
  console.log(`\n${c.bold}${c.cyan}━━ ${name} ━━${c.reset}`);
}

async function test(name: string, fn: () => Promise<{ ok: boolean; detail?: string; warn?: boolean }>): Promise<void> {
  const t0 = performance.now();
  let status: Status = 'PASS';
  let detail: string | undefined;
  try {
    const r = await fn();
    if (r.warn) {
      status = 'WARN';
    } else {
      status = r.ok ? 'PASS' : 'FAIL';
    }
    detail = r.detail;
  } catch (e: any) {
    status = 'FAIL';
    detail = e.message || String(e);
  }
  const ms = performance.now() - t0;
  results.push({ group: currentGroup, name, status, detail, ms });
  const icon = { PASS: `${c.green}✔`, FAIL: `${c.red}✘`, WARN: `${c.yellow}⚠`, SKIP: `${c.gray}○` }[status];
  const time = `${c.dim}${ms.toFixed(0)}ms${c.reset}`;
  const det  = detail ? `  ${c.dim}${detail}${c.reset}` : '';
  console.log(`  ${icon} ${c.reset}${name}  ${time}${det}`);
}

function skip(name: string, reason: string) {
  results.push({ group: currentGroup, name, status: 'SKIP', detail: reason, ms: 0 });
  console.log(`  ${c.gray}○ ${name}  ${c.dim}${reason}${c.reset}`);
}

// ─── 结构验证辅助 ──────────────────────────────────────────────────────────

/** 检查对象是否包含指定的所有键，返回缺失键列表 */
function hasKeys(obj: any, keys: string[]): string[] {
  if (!obj || typeof obj !== 'object') return ['（不是对象）'];
  return keys.filter(k => !(k in obj));
}

/** 验证 Bitwarden 列表格式 { data: [...], object: "list" } */
function expectList(body: any, objectName = 'list'): { ok: boolean; detail?: string } {
  const missing = hasKeys(body, ['data', 'object']);
  if (missing.length) return { ok: false, detail: `缺少字段: ${missing.join(', ')}` };
  if (body.object !== objectName) return { ok: false, detail: `object="${body.object}" 期望="${objectName}"` };
  if (!Array.isArray(body.data)) return { ok: false, detail: 'data 不是数组' };
  return { ok: true };
}

// ─── 客户端期望的关键响应字段清单 ──────────────────────────────────────────

// Profile：全平台客户端都会读取这些字段
const PROFILE_KEYS = [
  'id', 'name', 'email', 'emailVerified', 'premium', 'key', 'privateKey',
  'securityStamp', 'organizations', 'providers', 'providerOrganizations',
  'twoFactorEnabled', 'forcePasswordReset', 'culture', 'object', 'creationDate',
];

// Cipher：密码项响应的完整字段
const CIPHER_KEYS = [
  'id', 'type', 'name', 'favorite', 'reprompt', 'edit', 'viewPassword',
  'creationDate', 'revisionDate', 'object', 'collectionIds', 'organizationId',
  'permissions', 'deletedDate',
];

const FOLDER_KEYS = ['id', 'name', 'revisionDate', 'object'];

// Sync：全量同步的顶级字段
const SYNC_KEYS = [
  'profile', 'folders', 'collections', 'ciphers', 'domains',
  'policies', 'sends', 'object', 'UserDecryptionOptions', 'userDecryption',
];

// Token：登录/刷新响应的必需字段
const TOKEN_KEYS = [
  'access_token', 'expires_in', 'token_type', 'refresh_token',
  'Key', 'PrivateKey', 'Kdf', 'KdfIterations', 'scope', 'UserDecryptionOptions',
];

// ═══════════════════════════════════════════════════════════════════════════
//  测试套件
// ═══════════════════════════════════════════════════════════════════════════

// ─── 1. 服务器连通性 + Config 深度验证 ──────────────────────────────────────
// 验证服务器基础端点、Config 结构、favicon、DevTools 探针

async function suiteConnectivity() {
  group('1 · 服务器连通性');

  await test('GET /config 返回有效配置', async () => {
    const { status, body } = await api('/config', { auth: false });
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    const missing = hasKeys(body, ['version', 'environment', 'object']);
    if (missing.length) return { ok: false, detail: `缺少字段: ${missing.join(', ')}` };
    return { ok: body.object === 'config', detail: `版本 ${body.version}` };
  });

  await test('GET /api/config（别名路径）', async () => {
    const { status, body } = await api('/api/config', { auth: false });
    return { ok: status === 200 && body?.object === 'config' };
  });

  // Config.environment 所有 URL 字段必须指向服务器自身
  // 客户端用这些 URL 构建后续请求地址
  await test('Config.environment URL 一致性', async () => {
    const { body } = await api('/config', { auth: false });
    const env = body?.environment;
    if (!env) return { ok: false, detail: 'environment 缺失' };
    const checks = [
      env.vault && env.vault.startsWith('http'),
      env.api && env.api.includes('/api'),
      env.identity && env.identity.includes('/identity'),
      env.notifications && env.notifications.includes('/notifications'),
    ];
    return { ok: checks.every(Boolean), detail: `vault=${env.vault}` };
  });

  // featureStates 字段存在（客户端读取 feature flags）
  await test('Config.featureStates 存在', async () => {
    const { body } = await api('/config', { auth: false });
    return { ok: body?.featureStates && typeof body.featureStates === 'object' };
  });

  await test('GET /api/version 返回版本字符串', async () => {
    const { status, body } = await api('/api/version', { auth: false });
    return { ok: status === 200 && typeof body === 'string' && body.length > 0, detail: body };
  });

  await test('GET /favicon.ico 返回 SVG 图标', async () => {
    const resp = await fetch(`${BASE}/favicon.ico`);
    const ct = resp.headers.get('content-type') || '';
    const text = await resp.text();
    return { ok: resp.status === 200 && ct.includes('svg') && text.includes('<svg'), detail: ct };
  });

  await test('GET /favicon.svg 返回 SVG 图标', async () => {
    const resp = await fetch(`${BASE}/favicon.svg`);
    return { ok: resp.status === 200, detail: `状态码=${resp.status}` };
  });

  await test('GET /.well-known DevTools 探针端点', async () => {
    const { status } = await api('/.well-known/appspecific/com.chrome.devtools.json', { auth: false });
    return { ok: status === 200 };
  });
}

// ─── 2. CORS 深度验证 ──────────────────────────────────────────────────────
// 浏览器插件（Chrome/Firefox/Safari/Edge）依赖 CORS 头
// 缺少任何必需头都会导致插件请求被浏览器拦截

async function suiteCors() {
  group('2 · CORS 深度验证（浏览器插件必需）');

  await test('OPTIONS / 返回 204 + CORS 头', async () => {
    const resp = await fetch(`${BASE}/`, {
      method: 'OPTIONS',
      headers: { Origin: BASE },
    });
    const acao = resp.headers.get('access-control-allow-origin');
    return { ok: resp.status === 204 && acao === BASE };
  });

  // 浏览器插件请求 /identity/connect/token 前会发 OPTIONS 预检
  await test('OPTIONS /identity/connect/token CORS 预检', async () => {
    const resp = await fetch(`${BASE}/identity/connect/token`, { method: 'OPTIONS' });
    return { ok: resp.status === 204 };
  });

  // 浏览器插件请求 /api/sync 前也会预检
  await test('OPTIONS /api/sync CORS 预检', async () => {
    const resp = await fetch(`${BASE}/api/sync`, { method: 'OPTIONS' });
    return { ok: resp.status === 204 };
  });

  // Access-Control-Allow-Headers 必须包含这些头
  // Bitwarden 客户端会发送 Device-Type、Bitwarden-Client-Name 等自定义头
  await test('CORS Allow-Headers 包含全部必需头', async () => {
    const resp = await fetch(`${BASE}/`, { method: 'OPTIONS' });
    const ah = (resp.headers.get('access-control-allow-headers') || '').toLowerCase();
    const required = ['authorization', 'content-type', 'accept', 'device-type',
                      'bitwarden-client-name', 'bitwarden-client-version'];
    const missing = required.filter(h => !ah.includes(h));
    return { ok: missing.length === 0, detail: missing.length ? `缺少: ${missing.join(', ')}` : '全部包含' };
  });

  // Allow-Methods 必须包含所有 HTTP 方法
  await test('CORS Allow-Methods 包含 GET/POST/PUT/DELETE', async () => {
    const resp = await fetch(`${BASE}/`, { method: 'OPTIONS' });
    const am = (resp.headers.get('access-control-allow-methods') || '').toUpperCase();
    const required = ['GET', 'POST', 'PUT', 'DELETE'];
    const missing = required.filter(m => !am.includes(m));
    return { ok: missing.length === 0, detail: missing.length ? `缺少: ${missing.join(', ')}` : undefined };
  });

  // 实际 JSON 响应也必须带 CORS 头（不只是 OPTIONS）
  await test('JSON 响应包含 Access-Control-Allow-Origin（同源）', async () => {
    const resp = await fetch(`${BASE}/config`, {
      headers: { Origin: BASE },
    });
    const acao = resp.headers.get('access-control-allow-origin');
    return { ok: acao === BASE };
  });
}

// ─── 3. 注册与设置 ──────────────────────────────────────────────────────────

async function suiteRegistration() {
  group('3 · 注册与设置');

  await test('GET /setup/status 返回设置状态', async () => {
    const { status, body } = await api('/setup/status', { auth: false });
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    return { ok: 'registered' in body && 'disabled' in body, detail: `已注册=${body.registered}` };
  });

  // 用默认 KDF 参数计算密码哈希（注册时用默认参数）
  const defaultIter = 600000;
  masterPasswordHash = computePasswordHash(PASSWORD, EMAIL, 0, defaultIter);
  userEncKey = generateFakeEncKey();

  await test('POST /api/accounts/register（单用户注册）', async () => {
    const { status, body } = await api('/api/accounts/register', {
      method: 'POST', auth: false,
      body: {
        email: EMAIL, name: EMAIL.split('@')[0],
        masterPasswordHash, key: userEncKey,
        kdf: 0, kdfIterations: defaultIter, kdfMemory: null, kdfParallelism: null,
        keys: { publicKey: 'selfcheck-pubkey-placeholder', encryptedPrivateKey: 'selfcheck-privkey-placeholder' },
      },
    });
    if (status === 200) { isNewRegistration = true; return { ok: true, detail: '✓ 新用户创建成功' }; }
    if (status === 403) { return { ok: true, detail: '已有用户注册（正常）' }; }
    return { ok: false, detail: `状态码=${status} ${JSON.stringify(body)}` };
  });

  await test('POST /api/accounts/register 重复注册 → 403', async () => {
    const { status } = await api('/api/accounts/register', {
      method: 'POST', auth: false,
      body: {
        email: 'duplicate@test.com', masterPasswordHash: 'x', key: 'x',
        kdf: 0, kdfIterations: 600000,
        keys: { publicKey: 'x', encryptedPrivateKey: 'x' },
      },
    });
    return { ok: status === 403, detail: `状态码=${status}` };
  });
}

// ─── 4. 认证 ── 多客户端 + JWT Claims + 边界条件 ───────────────────────────
// 覆盖所有平台的登录行为差异

async function suiteAuth() {
  group('4 · 认证（多平台登录 + JWT 声明）');

  // 4.1 Prelogin
  await test('POST /identity/accounts/prelogin 返回 KDF 参数', async () => {
    const { status, body } = await api('/identity/accounts/prelogin', {
      method: 'POST', auth: false, body: { email: EMAIL },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    // 用服务器返回的真实 KDF 参数重新计算密码哈希
    masterPasswordHash = computePasswordHash(PASSWORD, EMAIL, body.kdf, body.kdfIterations);
    return { ok: true, detail: `kdf=${body.kdf} 迭代=${body.kdfIterations}` };
  });

  // 防枚举：不存在的用户也返回默认参数
  await test('Prelogin 不存在的用户 → 返回默认参数（防枚举）', async () => {
    const { status, body } = await api('/identity/accounts/prelogin', {
      method: 'POST', auth: false, body: { email: 'nobody-exists@test.com' },
    });
    return { ok: status === 200 && body.kdf === 0 && body.kdfIterations === 600000 };
  });

  // 4.2 密码登录（web client_id）
  await test('密码登录 client_id=web', async () => {
    const { status, body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: {
        grant_type: 'password', username: EMAIL, password: masterPasswordHash,
        scope: 'api offline_access', client_id: 'web',
      },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status} ${JSON.stringify(body)}` };
    const missing = hasKeys(body, TOKEN_KEYS);
    if (missing.length) return { ok: false, detail: `缺少字段: ${missing.join(', ')}` };
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
    userEncKey = body.Key;
    return { ok: true, detail: `有效期=${body.expires_in}s` };
  });

  // 4.3 不同 client_id 登录（模拟各平台客户端）
  // 浏览器插件用 browser，桌面端用 desktop，移动端用 mobile，CLI 用 cli
  for (const cid of ['browser', 'desktop', 'mobile', 'cli']) {
    await test(`密码登录 client_id=${cid}（${
      { browser: '浏览器插件', desktop: '桌面端', mobile: '移动端', cli: 'CLI' }[cid]
    }）`, async () => {
      const { status, body } = await api('/identity/connect/token', {
        method: 'POST', auth: false,
        form: {
          grant_type: 'password', username: EMAIL, password: masterPasswordHash,
          scope: 'api offline_access', client_id: cid,
        },
      });
      if (status !== 200) return { ok: false, detail: `状态码=${status}` };
      // 更新令牌到最新的
      accessToken = body.access_token;
      refreshToken = body.refresh_token;
      return { ok: !!body.access_token && !!body.Key };
    });
  }

  // 4.4 带设备头的登录（Android/iOS 会发送 deviceType、deviceName、deviceIdentifier）
  await test('带设备头登录（Android 设备参数）', async () => {
    const { status, body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: {
        grant_type: 'password', username: EMAIL, password: masterPasswordHash,
        scope: 'api offline_access', client_id: 'mobile',
        deviceType: '0', deviceName: 'Android', deviceIdentifier: 'selfcheck-device-id',
      },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
    return { ok: true };
  });

  // 4.5 JSON 格式登录（部分第三方客户端用 JSON 而非 form-urlencoded）
  await test('JSON 格式登录（非 form-urlencoded）', async () => {
    const { status, body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      body: {
        grant_type: 'password', username: EMAIL, password: masterPasswordHash,
        scope: 'api offline_access', client_id: 'web',
      },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
    return { ok: true };
  });

  // 4.6 错误密码
  await test('错误密码 → 400 invalid_grant', async () => {
    const { status, body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: { grant_type: 'password', username: EMAIL, password: 'wrong-hash' },
    });
    return { ok: status === 400 && body?.error === 'invalid_grant' };
  });

  // 4.7 缺少字段
  await test('缺少 grant_type → 400', async () => {
    const { status } = await api('/identity/connect/token', {
      method: 'POST', auth: false, form: { username: EMAIL, password: 'x' },
    });
    return { ok: status === 400 };
  });

  // 4.8 不支持的 grant_type
  await test('grant_type=client_credentials → 400', async () => {
    const { status } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: { grant_type: 'client_credentials', client_id: 'x', client_secret: 'x' },
    });
    return { ok: status === 400 };
  });

  // 4.9 JWT 内部声明验证
  // 移动端（Android/iOS）会解码 JWT 检查这些字段，缺失会导致认证失败
  await test('JWT payload 包含 email_verified=true（移动端必需）', async () => {
    const payload = decodeJwtPayload(accessToken);
    if (!payload) return { ok: false, detail: 'JWT 解码失败' };
    return { ok: payload.email_verified === true, detail: `email_verified=${payload.email_verified}` };
  });

  await test('JWT payload 包含 amr=["Application"]（移动端必需）', async () => {
    const payload = decodeJwtPayload(accessToken);
    if (!payload) return { ok: false, detail: 'JWT 解码失败' };
    return { ok: Array.isArray(payload.amr) && payload.amr.includes('Application') };
  });

  await test('JWT payload 包含 premium=true', async () => {
    const payload = decodeJwtPayload(accessToken);
    return { ok: payload?.premium === true };
  });

  await test('JWT payload 包含 sub / email / sstamp / iss', async () => {
    const payload = decodeJwtPayload(accessToken);
    if (!payload) return { ok: false, detail: 'JWT 解码失败' };
    const missing = ['sub', 'email', 'sstamp', 'iss'].filter(k => !(k in payload));
    return { ok: missing.length === 0, detail: missing.length ? `缺少: ${missing.join(', ')}` : undefined };
  });

  // 4.10 Token 响应的 UserDecryptionOptions 深度验证
  await test('Token.UserDecryptionOptions 嵌套结构完整', async () => {
    const { body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: { grant_type: 'password', username: EMAIL, password: masterPasswordHash },
    });
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
    const udo = body?.UserDecryptionOptions;
    if (!udo) return { ok: false, detail: 'UDO 缺失' };
    const mpu = udo.MasterPasswordUnlock;
    if (!mpu) return { ok: false, detail: 'MasterPasswordUnlock 缺失' };
    const checks = [
      udo.HasMasterPassword === true,
      mpu.Salt === EMAIL,
      mpu.MasterKeyWrappedUserKey != null,
      mpu.Kdf?.KdfType === 0,
      mpu.Kdf?.Iterations === 600000 || mpu.Kdf?.Iterations > 0,
    ];
    const failed = checks.filter(c => !c).length;
    return { ok: failed === 0, detail: failed ? `${failed} 项检查失败` : `Salt=${mpu.Salt}` };
  });
}

// ─── 5. 令牌刷新完整性 ─────────────────────────────────────────────────────
// 令牌刷新是客户端后台自动行为，响应结构必须与登录一致

async function suiteRefresh() {
  group('5 · 令牌刷新完整性');

  if (!refreshToken) { skip('全部刷新测试', '无刷新令牌'); return; }

  // 保存旧 refresh_token 用于后续的复用测试
  const oldRefreshToken = refreshToken;

  await test('刷新令牌 → 返回全部字段', async () => {
    const { status, body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: { grant_type: 'refresh_token', refresh_token: refreshToken },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    const missing = hasKeys(body, TOKEN_KEYS);
    if (missing.length) return { ok: false, detail: `缺少: ${missing.join(', ')}` };
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
    return { ok: true, detail: '令牌已轮换' };
  });

  // 刷新响应必须包含 UserDecryptionOptions（Android 空 vault 解锁依赖此）
  await test('刷新响应包含 UserDecryptionOptions', async () => {
    // 用新的 refresh_token 再刷新一次
    const { status, body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: { grant_type: 'refresh_token', refresh_token: refreshToken },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
    const udo = body?.UserDecryptionOptions;
    return { ok: !!udo && udo.HasMasterPassword === true && !!udo.MasterPasswordUnlock };
  });

  // 刷新响应必须包含 Key 和 PrivateKey（桌面端重建加密上下文需要）
  await test('刷新响应包含 Key 和 PrivateKey', async () => {
    // 通过上一次测试已更新了 accessToken，直接检查最近的响应
    const { body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: { grant_type: 'refresh_token', refresh_token: refreshToken },
    });
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
    return { ok: body?.Key != null && typeof body.Key === 'string' && body.Key.length > 0 };
  });

  // 安全性：旧的 refresh_token 不可复用（令牌轮换机制）
  await test('旧 refresh_token 不可复用（令牌轮换安全性）', async () => {
    const { status } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: { grant_type: 'refresh_token', refresh_token: oldRefreshToken },
    });
    return { ok: status === 400 || status === 401, detail: `状态码=${status}` };
  });
}

// ─── 6. 空保管库回归测试 ───────────────────────────────────────────────────
// 【关键场景】用户报告的 bug：刚注册、没有任何密码项，锁定后解锁报错。
//
// 复现路径：注册 → 登录 → sync（空数据）→ 锁定（前端丢弃密钥）→ 重新登录
// 本套件模拟这个完整流程，验证空 vault 状态下所有核心端点正常工作。
//
// 客户端锁定/解锁的本质：
//   锁定 = 前端丢弃内存中的 masterKey 和 encKey
//   解锁 = 用密码重新派生 masterKey → 调用 /identity/connect/token → 获取 Key → 解密
// 所以 "解锁失败" 的根因通常是 Token 响应中 Key 为空或 UDO 结构不完整。

async function suiteEmptyVault() {
  group('6 · 空保管库回归测试（锁定/解锁 bug 场景）');

  if (!accessToken) { skip('全部空保管库测试', '未获取到访问令牌'); return; }

  // 6.1 空 vault sync — 最核心的测试
  await test('空 vault GET /api/sync 结构完整', async () => {
    const { status, body } = await api('/api/sync');
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    const missing = hasKeys(body, SYNC_KEYS);
    if (missing.length) return { ok: false, detail: `缺少: ${missing.join(', ')}` };
    // 即使没有数据，数组字段也必须存在且为数组（不能是 null/undefined）
    const arrays = ['folders', 'collections', 'ciphers', 'policies', 'sends'];
    const nullArrays = arrays.filter(k => !Array.isArray(body[k]));
    if (nullArrays.length) return { ok: false, detail: `非数组字段: ${nullArrays.join(', ')}` };
    return { ok: body.object === 'sync' };
  });

  // 6.2 空 vault 下 ciphers 列表
  await test('空 vault GET /api/ciphers → 空列表', async () => {
    const { status, body } = await api('/api/ciphers');
    const r = expectList(body);
    if (!r.ok) return r;
    // 注意：可能上次测试残留了数据，这里只验证格式正确
    return { ok: status === 200, detail: `数量=${body.data.length}` };
  });

  // 6.3 空 vault 下 folders 列表
  await test('空 vault GET /api/folders → 空列表', async () => {
    const { status, body } = await api('/api/folders');
    const r = expectList(body);
    return { ok: status === 200 && r.ok, detail: `数量=${body.data.length}` };
  });

  // 6.4 空 vault 下 revision-date 仍然有效
  await test('空 vault revision-date 有效（>0）', async () => {
    const { status, body } = await api('/api/accounts/revision-date');
    return { ok: status === 200 && typeof body === 'number' && body > 0, detail: `时间戳=${body}` };
  });

  // 6.5 Sync.UserDecryptionOptions 深度验证（PascalCase — 桌面端/浏览器插件）
  await test('Sync.UserDecryptionOptions 嵌套结构（桌面端/浏览器插件）', async () => {
    const { body } = await api('/api/sync');
    const udo = body?.UserDecryptionOptions;
    if (!udo) return { ok: false, detail: 'UDO 缺失' };
    const mpu = udo.MasterPasswordUnlock;
    if (!mpu) return { ok: false, detail: 'MasterPasswordUnlock 缺失' };
    // Salt 必须等于用户邮箱，否则客户端 KDF 计算会出错
    if (mpu.Salt !== EMAIL) return { ok: false, detail: `Salt="${mpu.Salt}" 期望="${EMAIL}"` };
    // MasterKeyWrappedUserKey 不能为 null（这是解锁的关键数据）
    if (!mpu.MasterKeyWrappedUserKey) return { ok: false, detail: 'MasterKeyWrappedUserKey 为空' };
    // Kdf 结构
    if (!mpu.Kdf) return { ok: false, detail: 'Kdf 缺失' };
    if (typeof mpu.Kdf.KdfType !== 'number') return { ok: false, detail: 'Kdf.KdfType 缺失' };
    return { ok: true, detail: `KdfType=${mpu.Kdf.KdfType} Iterations=${mpu.Kdf.Iterations}` };
  });

  // 6.6 Sync.userDecryption 深度验证（camelCase — Android 专用）
  await test('Sync.userDecryption 嵌套结构（Android 客户端）', async () => {
    const { body } = await api('/api/sync');
    const ud = body?.userDecryption;
    if (!ud) return { ok: false, detail: 'userDecryption 缺失' };
    const mpu = ud.masterPasswordUnlock;
    if (!mpu) return { ok: false, detail: 'masterPasswordUnlock 缺失' };
    if (mpu.salt !== EMAIL) return { ok: false, detail: `salt="${mpu.salt}" 期望="${EMAIL}"` };
    if (!mpu.masterKeyWrappedUserKey) return { ok: false, detail: 'masterKeyWrappedUserKey 为空' };
    if (!mpu.kdf) return { ok: false, detail: 'kdf 缺失' };
    if (typeof mpu.kdf.kdfType !== 'number') return { ok: false, detail: 'kdf.kdfType 缺失' };
    return { ok: true };
  });

  // 6.7 Sync.domains 结构（不能为 null）
  await test('Sync.domains 结构完整', async () => {
    const { body } = await api('/api/sync');
    const d = body?.domains;
    if (!d) return { ok: false, detail: 'domains 缺失' };
    return {
      ok: d.object === 'domains'
        && Array.isArray(d.equivalentDomains)
        && Array.isArray(d.globalEquivalentDomains),
    };
  });

  // 6.8 模拟锁定后解锁（本质是重新登录 → 获取完整 Token 响应）
  await test('模拟解锁：重新登录获取 Key（锁定/解锁核心）', async () => {
    const { status, body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: {
        grant_type: 'password', username: EMAIL, password: masterPasswordHash,
        scope: 'api offline_access', client_id: 'web',
      },
    });
    if (status !== 200) return { ok: false, detail: `登录失败 状态码=${status}` };
    // Key 必须非空且格式有效（这是解锁失败的常见根因）
    if (!body.Key || typeof body.Key !== 'string' || body.Key.length < 10) {
      return { ok: false, detail: `Key 无效: "${body.Key}"` };
    }
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
    return { ok: true, detail: `Key 长度=${body.Key.length}` };
  });

  // 6.9 解锁后 sync 正常
  await test('解锁后 sync 正常', async () => {
    const { status, body } = await api('/api/sync');
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    const ok = body?.object === 'sync' && body?.profile?.email === EMAIL;
    return { ok };
  });

  // 6.10 Profile 的 key 字段非空（解锁时用于初始化加密上下文）
  await test('Profile.key 非空（加密上下文初始化依赖）', async () => {
    const { body } = await api('/api/accounts/profile');
    return { ok: body?.key != null && typeof body.key === 'string' && body.key.length > 10 };
  });
}

// ─── 7. 账户端点 ────────────────────────────────────────────────────────────

async function suiteAccounts() {
  group('7 · 账户端点');

  if (!accessToken) { skip('全部账户测试', '未获取到访问令牌'); return; }

  await test('GET /api/accounts/profile 获取用户资料', async () => {
    const { status, body } = await api('/api/accounts/profile');
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    const missing = hasKeys(body, PROFILE_KEYS);
    if (missing.length) return { ok: false, detail: `缺少: ${missing.join(', ')}` };
    userId = body.id;
    return { ok: body.object === 'profile' && body.email === EMAIL, detail: `id=${userId}` };
  });

  // Profile 详细字段验证
  await test('Profile 字段类型正确', async () => {
    const { body } = await api('/api/accounts/profile');
    const checks: [string, boolean][] = [
      ['emailVerified=true', body.emailVerified === true],
      ['premium=true', body.premium === true],
      ['twoFactorEnabled=bool', typeof body.twoFactorEnabled === 'boolean'],
      ['forcePasswordReset=false', body.forcePasswordReset === false],
      ['organizations=array', Array.isArray(body.organizations)],
      ['providers=array', Array.isArray(body.providers)],
      ['providerOrganizations=array', Array.isArray(body.providerOrganizations)],
      ['culture=string', typeof body.culture === 'string'],
    ];
    const failed = checks.filter(([, ok]) => !ok).map(([name]) => name);
    return { ok: failed.length === 0, detail: failed.length ? `失败: ${failed.join(', ')}` : undefined };
  });

  await test('PUT /api/accounts/profile 更新用户资料', async () => {
    const { status, body } = await api('/api/accounts/profile', {
      method: 'PUT', body: { name: 'SelfCheck Updated', masterPasswordHint: null },
    });
    return { ok: status === 200 && body?.object === 'profile' };
  });

  await test('POST /api/accounts/keys 更新密钥', async () => {
    const current = await api('/api/accounts/profile');
    if (current.status !== 200 || !current.body?.key || !current.body?.privateKey) {
      return { ok: false, detail: '无法读取当前 key/privateKey' };
    }
    const { status, body } = await api('/api/accounts/keys', {
      method: 'POST',
      // Non-destructive roundtrip: submit current encrypted keys as-is.
      body: { key: current.body.key, encryptedPrivateKey: current.body.privateKey },
    });
    return { ok: status === 200 && body?.object === 'profile' };
  });

  await test('GET /api/accounts/revision-date 时间戳', async () => {
    const { status, body } = await api('/api/accounts/revision-date');
    return { ok: status === 200 && typeof body === 'number' && body > 0, detail: `时间戳=${body}` };
  });

  await test('POST /api/accounts/verify-password 正确密码 → 200', async () => {
    const { status } = await api('/api/accounts/verify-password', {
      method: 'POST', body: { masterPasswordHash },
    });
    return { ok: status === 200 };
  });

  await test('POST /api/accounts/verify-password 错误密码 → 400', async () => {
    const { status } = await api('/api/accounts/verify-password', {
      method: 'POST', body: { masterPasswordHash: 'wrong-hash-value' },
    });
    return { ok: status === 400 };
  });
}

// ─── 8. 同步深度验证 ───────────────────────────────────────────────────────

async function suiteSync() {
  group('8 · 同步深度验证');

  if (!accessToken) { skip('全部同步测试', '未获取到访问令牌'); return; }

  await test('GET /api/sync 完整同步', async () => {
    const { status, body } = await api('/api/sync');
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    const missing = hasKeys(body, SYNC_KEYS);
    if (missing.length) return { ok: false, detail: `缺少: ${missing.join(', ')}` };
    const pMissing = hasKeys(body.profile, PROFILE_KEYS);
    if (pMissing.length) return { ok: false, detail: `profile 缺少: ${pMissing.join(', ')}` };
    return { ok: body.object === 'sync' };
  });

  // Sync.profile 与独立 Profile 一致性
  await test('Sync.profile 与 GET /api/accounts/profile 一致', async () => {
    const [sync, profile] = await Promise.all([api('/api/sync'), api('/api/accounts/profile')]);
    const sp = sync.body?.profile;
    const pp = profile.body;
    return { ok: sp?.id === pp?.id && sp?.email === pp?.email && sp?.key === pp?.key };
  });
}

// ─── 9. 文件夹 CRUD ─────────────────────────────────────────────────────────

async function suiteFolders() {
  group('9 · 文件夹');

  if (!accessToken) { skip('全部文件夹测试', '未获取到访问令牌'); return; }

  await test('POST /api/folders 创建', async () => {
    const { status, body } = await api('/api/folders', {
      method: 'POST', body: { name: '2.自查测试文件夹==' },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    const missing = hasKeys(body, FOLDER_KEYS);
    if (missing.length) return { ok: false, detail: `缺少: ${missing.join(', ')}` };
    testFolderId = body.id;
    return { ok: body.object === 'folder', detail: `id=${testFolderId}` };
  });

  await test('GET /api/folders 列表', async () => {
    const { status, body } = await api('/api/folders');
    const r = expectList(body);
    if (!r.ok) return r;
    return { ok: body.data.length >= 1, detail: `数量=${body.data.length}` };
  });

  await test('GET /api/folders/:id 单个', async () => {
    if (!testFolderId) return { ok: false, detail: '无可用文件夹' };
    const { status, body } = await api(`/api/folders/${testFolderId}`);
    return { ok: status === 200 && body?.id === testFolderId };
  });

  await test('PUT /api/folders/:id 更新', async () => {
    if (!testFolderId) return { ok: false, detail: '无可用文件夹' };
    const { status, body } = await api(`/api/folders/${testFolderId}`, {
      method: 'PUT', body: { name: '2.更新后文件夹==' },
    });
    return { ok: status === 200 && body?.object === 'folder' };
  });
}

// ─── 10. 密码项 CRUD + 边界条件 ─────────────────────────────────────────────

async function suiteCiphers() {
  group('10 · 密码项（Ciphers）');

  if (!accessToken) { skip('全部密码项测试', '未获取到访问令牌'); return; }

  // 记录创建前的 revision-date，用于后面验证递增
  let revDateBefore = 0;
  {
    const { body } = await api('/api/accounts/revision-date');
    if (typeof body === 'number') revDateBefore = body;
  }

  // --- 创建：四种类型 ---

  await test('POST /api/ciphers 创建 Login 类型', async () => {
    const { status, body } = await api('/api/ciphers', {
      method: 'POST',
      body: {
        type: 1, name: '2.测试登录项==', notes: '2.备注内容==',
        folderId: testFolderId || null, favorite: true, reprompt: 0,
        login: {
          username: '2.用户名==', password: '2.密码==',
          uris: [{ uri: '2.https://example.com==', match: null }], totp: null,
        },
        fields: [{ name: '2.自定义字段==', value: '2.值==', type: 0, linkedId: null }],
        passwordHistory: [{ password: '2.旧密码==', lastUsedDate: new Date().toISOString() }],
      },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status} ${JSON.stringify(body)}` };
    const missing = hasKeys(body, CIPHER_KEYS);
    if (missing.length) return { ok: false, detail: `缺少: ${missing.join(', ')}` };
    testCipherId = body.id;
    allCreatedCipherIds.push(body.id);
    return { ok: body.object === 'cipher' && body.type === 1, detail: `id=${testCipherId}` };
  });

  await test('POST /api/ciphers 创建 SecureNote', async () => {
    const { status, body } = await api('/api/ciphers', {
      method: 'POST', body: { type: 2, name: '2.安全笔记==', secureNote: { type: 0 }, reprompt: 0 },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    testCipher2Id = body.id;
    allCreatedCipherIds.push(body.id);
    return { ok: body.type === 2, detail: `id=${testCipher2Id}` };
  });

  await test('POST /api/ciphers 创建 Card', async () => {
    const { status, body } = await api('/api/ciphers', {
      method: 'POST',
      body: {
        type: 3, name: '2.银行卡==', reprompt: 0,
        card: { cardholderName: '2.持卡人==', number: '2.卡号==', brand: '2.Visa==',
                expMonth: '2.01==', expYear: '2.2030==', code: '2.123==' },
      },
    });
    if (body?.id) allCreatedCipherIds.push(body.id);
    return { ok: status === 200 && body?.type === 3 };
  });

  await test('POST /api/ciphers 创建 Identity', async () => {
    const { status, body } = await api('/api/ciphers', {
      method: 'POST',
      body: {
        type: 4, name: '2.身份信息==', reprompt: 0,
        identity: { firstName: '2.名==', lastName: '2.姓==', email: '2.邮箱==' },
      },
    });
    if (body?.id) allCreatedCipherIds.push(body.id);
    return { ok: status === 200 && body?.type === 4 };
  });

  // 部分客户端用 { cipher: {...} } 嵌套格式
  await test('POST /api/ciphers/create 嵌套格式', async () => {
    const { status, body } = await api('/api/ciphers/create', {
      method: 'POST',
      body: { cipher: { type: 2, name: '2.嵌套创建==', secureNote: { type: 0 }, reprompt: 0 } },
    });
    if (body?.id) allCreatedCipherIds.push(body.id);
    return { ok: status === 200 && body?.object === 'cipher' };
  });

  // --- 响应字段深度验证 ---

  await test('Cipher 响应字段完整性', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { body } = await api(`/api/ciphers/${testCipherId}`);
    const checks: [string, boolean][] = [
      ['organizationId=null', body.organizationId === null],
      ['edit=true', body.edit === true],
      ['viewPassword=true', body.viewPassword === true],
      ['collectionIds=[]', Array.isArray(body.collectionIds) && body.collectionIds.length === 0],
      ['permissions.delete=true', body.permissions?.delete === true],
      ['permissions.restore=true', body.permissions?.restore === true],
      ['deletedDate=null', body.deletedDate === null],
    ];
    const failed = checks.filter(([, ok]) => !ok).map(([name]) => name);
    return { ok: failed.length === 0, detail: failed.length ? `失败: ${failed.join(', ')}` : undefined };
  });

  // --- 读取 ---

  await test('GET /api/ciphers 列表', async () => {
    const { status, body } = await api('/api/ciphers');
    const r = expectList(body);
    if (!r.ok) return r;
    return { ok: body.data.length >= 4, detail: `数量=${body.data.length}` };
  });

  await test('GET /api/ciphers/:id 单个', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status, body } = await api(`/api/ciphers/${testCipherId}`);
    return { ok: status === 200 && body?.id === testCipherId };
  });

  await test('GET /api/ciphers/:id/details 详情', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status, body } = await api(`/api/ciphers/${testCipherId}/details`);
    return { ok: status === 200 && body?.id === testCipherId };
  });

  // --- 更新 ---

  await test('PUT /api/ciphers/:id 更新', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status, body } = await api(`/api/ciphers/${testCipherId}`, {
      method: 'PUT',
      body: { type: 1, name: '2.已更新==', reprompt: 0,
              login: { username: '2.新用户名==', password: '2.新密码==', uris: [] } },
    });
    return { ok: status === 200 && body?.object === 'cipher' };
  });

  // POST 方式更新（部分 Android 客户端行为）
  await test('POST /api/ciphers/:id 更新（POST 别名）', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status, body } = await api(`/api/ciphers/${testCipherId}`, {
      method: 'POST',
      body: { type: 1, name: '2.POST更新==', reprompt: 0,
              login: { username: '2.u==', password: '2.p==', uris: [] } },
    });
    return { ok: status === 200 && body?.object === 'cipher' };
  });

  await test('PUT /api/ciphers/:id/partial 部分更新', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status, body } = await api(`/api/ciphers/${testCipherId}/partial`, {
      method: 'PUT', body: { favorite: false, folderId: null },
    });
    return { ok: status === 200 && body?.favorite === false };
  });

  await test('POST /api/ciphers/:id/share（单用户 stub）', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status, body } = await api(`/api/ciphers/${testCipherId}/share`, { method: 'POST', body: {} });
    return { ok: status === 200 && body?.object === 'cipher' };
  });

  // --- revision-date 递增验证 ---

  await test('写操作后 revision-date 递增', async () => {
    const { body } = await api('/api/accounts/revision-date');
    if (typeof body !== 'number') return { ok: false, detail: '返回非数字' };
    return { ok: body >= revDateBefore, detail: `前=${revDateBefore} 后=${body}` };
  });

  // --- 软删除、恢复、永久删除 ---

  await test('DELETE /api/ciphers/:id 软删除', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status, body } = await api(`/api/ciphers/${testCipherId}`, { method: 'DELETE' });
    return { ok: status === 200 && body?.deletedDate != null };
  });

  await test('PUT /api/ciphers/:id/restore 恢复', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status, body } = await api(`/api/ciphers/${testCipherId}/restore`, { method: 'PUT' });
    return { ok: status === 200 && body?.deletedDate === null };
  });

  await test('PUT /api/ciphers/:id/delete 软删除（别名）', async () => {
    if (!testCipher2Id) return { ok: false, detail: '无可用密码项' };
    const { status, body } = await api(`/api/ciphers/${testCipher2Id}/delete`, { method: 'PUT' });
    return { ok: status === 200 && body?.deletedDate != null };
  });

  // 验证 deleted 过滤功能
  await test('GET /api/ciphers 默认不含已删除项', async () => {
    const { body } = await api('/api/ciphers');
    const hasDeleted = body?.data?.some((c: any) => c.deletedDate != null);
    return { ok: !hasDeleted, detail: hasDeleted ? '包含已删除项' : undefined };
  });

  await test('GET /api/ciphers?deleted=true 包含已删除项', async () => {
    const { body } = await api('/api/ciphers?deleted=true');
    // 至少有一个被软删除的项（testCipher2Id）
    const hasDeleted = body?.data?.some((c: any) => c.deletedDate != null);
    return { ok: body?.data?.length > 0 && hasDeleted, detail: `数量=${body?.data?.length}` };
  });

  await test('DELETE /api/ciphers/:id/delete 永久删除', async () => {
    if (!testCipher2Id) return { ok: false, detail: '无可用密码项' };
    const { status } = await api(`/api/ciphers/${testCipher2Id}/delete`, { method: 'DELETE' });
    return { ok: status === 204 || status === 200 };
  });

  await test('永久删除后 → 404', async () => {
    if (!testCipher2Id) return { ok: false, detail: '无可用密码项' };
    const { status } = await api(`/api/ciphers/${testCipher2Id}`);
    return { ok: status === 404 };
  });

  // --- 批量操作 ---

  await test('POST /api/ciphers/move 批量移动', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status } = await api('/api/ciphers/move', {
      method: 'POST', body: { ids: [testCipherId], folderId: testFolderId || null },
    });
    return { ok: status === 204 || status === 200 };
  });

  // PUT 也应该支持（部分桌面端行为）
  await test('PUT /api/ciphers/move 批量移动（PUT 别名）', async () => {
    if (!testCipherId) return { ok: false, detail: '无可用密码项' };
    const { status } = await api('/api/ciphers/move', {
      method: 'PUT', body: { ids: [testCipherId], folderId: null },
    });
    return { ok: status === 204 || status === 200 };
  });

  await test('POST /api/ciphers/import 批量导入', async () => {
    const { status, body } = await api('/api/ciphers/import', {
      method: 'POST',
      body: {
        ciphers: [{ type: 1, name: '2.导入项==', login: { username: '2.u==', password: '2.p==' }, reprompt: 0 }],
        folders: [{ name: '2.导入文件夹==' }],
        folderRelationships: [{ key: 0, value: 0 }],
      },
    });
    // Track imported ciphers/folders for cleanup
    if (body?.ciphers) for (const c of body.ciphers) { if (c?.id) allCreatedCipherIds.push(c.id); }
    if (body?.folders) for (const f of body.folders) { if (f?.id) allCreatedFolderIds.push(f.id); }
    return { ok: status === 200, detail: `状态码=${status}` };
  });
}

// ─── 11. 附件 ───────────────────────────────────────────────────────────────

async function suiteAttachments() {
  group('11 · 附件');

  if (!accessToken || !testCipherId) { skip('全部附件测试', '无可用令牌或密码项'); return; }

  // v2 端点（新版客户端标准流程）
  await test('POST /api/ciphers/:id/attachment/v2 创建元数据', async () => {
    const { status, body } = await api(`/api/ciphers/${testCipherId}/attachment/v2`, {
      method: 'POST', body: { fileName: '2.测试文件.txt==', key: '2.附件密钥==', fileSize: 42 },
    });
    if (status !== 200) return { ok: false, detail: `状态码=${status} ${JSON.stringify(body)}` };
    testAttachmentId = body.attachmentId;
    return { ok: !!testAttachmentId && body.object === 'attachment-fileUpload' && !!body.url,
             detail: `id=${testAttachmentId}` };
  });

  await test('POST /api/ciphers/:id/attachment/:aid 上传文件', async () => {
    if (!testAttachmentId) return { ok: false, detail: '未创建附件' };
    const formData = new FormData();
    formData.append('data', new Blob([new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f])]), 'test.bin');
    const resp = await fetch(`${BASE}/api/ciphers/${testCipherId}/attachment/${testAttachmentId}`, {
      method: 'POST', headers: { 'Authorization': `Bearer ${accessToken}` }, body: formData,
    });
    return { ok: resp.status === 200, detail: `状态码=${resp.status}` };
  });

  // 上传后验证附件出现在 cipher 的 attachments 数组中
  await test('上传后 cipher.attachments 非空（Android 依赖）', async () => {
    const { body } = await api(`/api/ciphers/${testCipherId}`);
    const atts = body?.attachments;
    if (!Array.isArray(atts) || atts.length === 0) return { ok: false, detail: 'attachments 为空' };
    const att = atts[0];
    // Android 要求 url 非 null，size 为数字
    const checks = [
      typeof att.url === 'string' && att.url.length > 0,
      typeof att.size === 'number',
      typeof att.fileName === 'string',
    ];
    const ok = checks.every(Boolean);
    return { ok, detail: ok ? `url=${att.url} size=${att.size}` : 'url/size 格式不符' };
  });

  // 获取下载链接
  await test('GET /api/ciphers/:id/attachment/:aid 下载链接', async () => {
    if (!testAttachmentId) return { ok: false, detail: '未创建附件' };
    const { status, body } = await api(`/api/ciphers/${testCipherId}/attachment/${testAttachmentId}`);
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    const ok = body.object === 'attachment' && typeof body.url === 'string' && body.url.includes('token=');
    if (ok) {
      const u = new URL(body.url);
      downloadToken = u.searchParams.get('token') || '';
    }
    return { ok };
  });

  // 公开下载
  await test('GET /api/attachments/:cid/:aid?token= 公开下载', async () => {
    if (!downloadToken) return { ok: false, detail: '无下载令牌' };
    const resp = await fetch(`${BASE}/api/attachments/${testCipherId}/${testAttachmentId}?token=${downloadToken}`);
    return { ok: resp.status === 200, detail: `状态码=${resp.status}` };
  });

  // 安全性：无 token 的下载应被拒绝
  await test('公开下载无 token → 401', async () => {
    const resp = await fetch(`${BASE}/api/attachments/${testCipherId}/${testAttachmentId}`);
    return { ok: resp.status === 401, detail: `状态码=${resp.status}` };
  });

  // 安全性：无效 token 的下载应被拒绝
  await test('公开下载无效 token → 401', async () => {
    const resp = await fetch(`${BASE}/api/attachments/${testCipherId}/${testAttachmentId}?token=invalid-garbage`);
    return { ok: resp.status === 401, detail: `状态码=${resp.status}` };
  });

  // 旧版附件端点（旧版桌面客户端用这个路径）
  await test('POST /api/ciphers/:id/attachment 旧版端点', async () => {
    const { status } = await api(`/api/ciphers/${testCipherId}/attachment`, {
      method: 'POST', body: { fileName: '2.旧版附件==', key: '2.key==', fileSize: 10 },
    });
    // 路由器已路由到同一 handler，应返回 200
    return { ok: status === 200, detail: `状态码=${status}` };
  });

  // 删除附件
  await test('DELETE /api/ciphers/:id/attachment/:aid 删除', async () => {
    if (!testAttachmentId) return { ok: false, detail: '未创建附件' };
    const { status } = await api(`/api/ciphers/${testCipherId}/attachment/${testAttachmentId}`, {
      method: 'DELETE',
    });
    return { ok: status === 200, detail: `状态码=${status}` };
  });
}

// ─── 12. Stub 端点 + 通知 + 子路径 ─────────────────────────────────────────
// 这些端点没有完整实现，但客户端会请求它们
// 必须返回正确格式的空数据，否则客户端报错

async function suiteStubs() {
  group('12 · Stub 端点（客户端兼容性）');

  if (!accessToken) { skip('全部 Stub 测试', '未获取到访问令牌'); return; }

  const stubs: [string, string, string][] = [
    ['GET', '/api/collections',   'Collections（集合）'],
    ['GET', '/api/organizations', 'Organizations（组织）'],
    ['GET', '/api/sends',         'Sends（安全发送）'],
    ['GET', '/api/policies',      'Policies（策略）'],
    ['GET', '/api/auth-requests', 'Auth Requests（认证请求）'],
    ['GET', '/api/devices',       'Devices（设备）'],
  ];

  for (const [method, path, label] of stubs) {
    await test(`${method} ${path} → 空列表 stub（${label}）`, async () => {
      const { status, body } = await api(path, { method });
      const r = expectList(body);
      return { ok: status === 200 && r.ok && body.data.length === 0, detail: r.detail ? r.detail : 'stub 占位' };
    });
  }

  // Stub 子路径测试（客户端可能请求带 ID 的子路径）
  const subPaths: [string, string][] = [
    ['/api/organizations/00000000-0000-0000-0000-000000000000', '组织子路径'],
    ['/api/collections/00000000-0000-0000-0000-000000000000', '集合子路径'],
    ['/api/sends/00000000-0000-0000-0000-000000000000', '发送子路径'],
    ['/api/policies/00000000-0000-0000-0000-000000000000', '策略子路径'],
  ];

  for (const [path, label] of subPaths) {
    await test(`GET ${path}（${label}）→ 不崩溃`, async () => {
      const { status } = await api(path);
      // 200 空列表或 404 都可以接受，关键是不能 500
      return { ok: status !== 500, detail: `状态码=${status}` };
    });
  }

  // 域名设置
  await test('GET /api/settings/domains → domains 对象', async () => {
    const { status, body } = await api('/api/settings/domains');
    return {
      ok: status === 200 && body?.object === 'domains'
        && Array.isArray(body.equivalentDomains)
        && Array.isArray(body.globalEquivalentDomains),
    };
  });

  await test('PUT /api/settings/domains 更新', async () => {
    const { status, body } = await api('/api/settings/domains', {
      method: 'PUT', body: { equivalentDomains: [], globalEquivalentDomains: [] },
    });
    return { ok: status === 200 && body?.object === 'domains' };
  });

  // POST 别名（旧版客户端）
  await test('POST /api/settings/domains（POST 别名）', async () => {
    const { status, body } = await api('/api/settings/domains', {
      method: 'POST', body: { equivalentDomains: [], globalEquivalentDomains: [] },
    });
    return { ok: status === 200 && body?.object === 'domains' };
  });

  // 通知端点 — 桌面端和浏览器插件启动时必调
  await test('GET /notifications/hub → 200', async () => {
    const resp = await fetch(`${BASE}/notifications/hub`);
    return { ok: resp.status === 200 };
  });

  // POST /notifications/hub/negotiate — SignalR 协商（桌面端/浏览器插件）
  // 客户端启动时会发 POST 请求进行 SignalR 握手
  await test('POST /notifications/hub/negotiate → 200（SignalR 协商）', async () => {
    const resp = await fetch(`${BASE}/notifications/hub/negotiate`, { method: 'POST' });
    return { ok: resp.status === 200, detail: `状态码=${resp.status}` };
  });

  // POST /notifications/hub — SignalR WebSocket 回退
  await test('POST /notifications/hub → 200（SignalR 回退）', async () => {
    const resp = await fetch(`${BASE}/notifications/hub`, { method: 'POST' });
    return { ok: resp.status === 200 };
  });

  // 带查询参数的通知路径
  await test('GET /notifications/hub?id=xxx → 200（长轮询）', async () => {
    const resp = await fetch(`${BASE}/notifications/hub?id=some-connection-id`);
    return { ok: resp.status === 200 };
  });

  // 设备已知检查
  await test('GET /api/devices/knowndevice → "true"', async () => {
    const resp = await fetch(`${BASE}/api/devices/knowndevice`);
    const text = await resp.text();
    return { ok: resp.status === 200 && text.trim() === 'true' };
  });

  // 带设备头的 knowndevice（iOS/Android 会附加这些头）
  await test('GET /api/devices/knowndevice + Device 头', async () => {
    const resp = await fetch(`${BASE}/api/devices/knowndevice`, {
      headers: {
        'X-Device-Identifier': 'selfcheck-device',
        'X-Request-Email': Buffer.from(EMAIL).toString('base64'),
      },
    });
    const text = await resp.text();
    return { ok: resp.status === 200 && (text.trim() === 'true' || text.trim() === 'false') };
  });
}

// ─── 13. 图标代理 ──────────────────────────────────────────────────────────

async function suiteIcons() {
  group('13 · 图标代理');

  await test('GET /icons/google.com/icon.png', async () => {
    const resp = await fetch(`${BASE}/icons/google.com/icon.png`);
    return { ok: resp.status === 200 || resp.status === 204, detail: `状态码=${resp.status}` };
  });
}

// ─── 14. 认证守卫 ──────────────────────────────────────────────────────────

async function suiteAuthGuard() {
  group('14 · 认证守卫');

  await test('GET /api/sync 无令牌 → 401', async () => {
    const { status } = await api('/api/sync', { auth: false });
    return { ok: status === 401 };
  });

  await test('GET /api/ciphers 无效令牌 → 401', async () => {
    const { status } = await api('/api/ciphers', {
      auth: false, headers: { 'Authorization': 'Bearer invalid.jwt.token' },
    });
    return { ok: status === 401 };
  });

  await test('GET /api/accounts/profile 无令牌 → 401', async () => {
    const { status } = await api('/api/accounts/profile', { auth: false });
    return { ok: status === 401 };
  });

  await test('POST /api/ciphers 无令牌 → 401', async () => {
    const { status } = await api('/api/ciphers', {
      method: 'POST', auth: false, body: { type: 1, name: 'x', reprompt: 0 },
    });
    return { ok: status === 401 };
  });
}

// ─── 15. 被阻止端点完整验证 ────────────────────────────────────────────────
// 单用户模式下禁止修改密码和删除账户
// 路由器阻止了多个路径 × 多种 HTTP 方法

async function suiteBlocked() {
  group('15 · 被阻止端点（单用户模式）');

  if (!accessToken) { skip('全部阻止测试', '未获取到访问令牌'); return; }

  // POST 方法
  const blockedPaths = [
    '/api/accounts/password',
    '/api/accounts/change-password',
    '/api/accounts/set-password',
    '/api/accounts/master-password',
    '/api/accounts/delete',
    '/api/accounts/delete-account',
    '/api/accounts/delete-vault',
  ];

  for (const path of blockedPaths) {
    await test(`POST ${path} → 501`, async () => {
      const { status } = await api(path, { method: 'POST', body: {} });
      return { ok: status === 501, detail: `状态码=${status}` };
    });
  }

  // PUT 和 DELETE 也应该被阻止（路由器检查 POST|PUT|DELETE）
  await test('PUT /api/accounts/password → 501', async () => {
    const { status } = await api('/api/accounts/password', { method: 'PUT', body: {} });
    return { ok: status === 501, detail: `状态码=${status}` };
  });

  await test('DELETE /api/accounts/delete → 501', async () => {
    const { status } = await api('/api/accounts/delete', { method: 'DELETE' });
    return { ok: status === 501, detail: `状态码=${status}` };
  });
}

// ─── 16. 响应结构合规性 ────────────────────────────────────────────────────

async function suiteResponseSchema() {
  group('16 · 响应结构合规性');

  await test('错误响应符合 Bitwarden ErrorModel 格式', async () => {
    const { body } = await api('/api/ciphers/00000000-0000-0000-0000-000000000000');
    const ok = body?.ErrorModel && body.ErrorModel.Object === 'error' && typeof body.ErrorModel.Message === 'string';
    return { ok: !!ok, detail: ok ? 'ErrorModel 正确' : `内容=${JSON.stringify(body).substring(0, 100)}` };
  });

  await test('Identity 错误响应符合 OAuth2 格式', async () => {
    const { body } = await api('/identity/connect/token', {
      method: 'POST', auth: false,
      form: { grant_type: 'password', username: EMAIL, password: 'wrong-hash' },
    });
    return { ok: typeof body?.error === 'string' && typeof body?.error_description === 'string' };
  });

  // 404 端点也应返回 JSON（不是纯文本）
  await test('404 返回 JSON ErrorModel', async () => {
    const { status, body } = await api('/api/nonexistent-endpoint-12345');
    return {
      ok: status === 404 && body?.ErrorModel?.Object === 'error',
      detail: typeof body === 'string' ? 'HTML/纯文本' : 'JSON',
    };
  });

  // 401 端点返回 JSON
  await test('401 返回 JSON ErrorModel', async () => {
    const { body } = await api('/api/sync', { auth: false });
    return { ok: body?.ErrorModel?.Object === 'error' };
  });
}

// ─── 17. 清理 ──────────────────────────────────────────────────────────────

async function suiteCleanup() {
  group('17 · 清理与最终验证');

  if (!accessToken) { skip('清理', '未获取到访问令牌'); return; }

  // Permanently delete ALL test-created ciphers to avoid "[error: cannot decrypt]" leftovers.
  // Collect any remaining ciphers from a sync in case some IDs were not tracked (e.g. import).
  try {
    const { body } = await api('/api/sync');
    if (body?.ciphers) {
      for (const c of body.ciphers) {
        if (c?.id && !allCreatedCipherIds.includes(c.id)) {
          // Check if this cipher has a fake encrypted name (our test marker)
          const n = c.name || '';
          if (n.startsWith('2.') && (n.endsWith('==') || n.endsWith('='))) {
            allCreatedCipherIds.push(c.id);
          }
        }
      }
      // Also find orphan test folders from import
      for (const f of (body.folders || [])) {
        if (f?.id && f.id !== testFolderId && !allCreatedFolderIds.includes(f.id)) {
          const n = f.name || '';
          if (n.startsWith('2.') && (n.endsWith('==') || n.endsWith('='))) {
            allCreatedFolderIds.push(f.id);
          }
        }
      }
    }
  } catch { /* best effort */ }

  // Delete all tracked ciphers
  const cipherIds = [...new Set(allCreatedCipherIds)];
  if (cipherIds.length > 0) {
    await test(`永久删除所有测试密码项 (${cipherIds.length} 个)`, async () => {
      let deleted = 0;
      for (const id of cipherIds) {
        // Soft-delete first (required for permanent delete if not already soft-deleted)
        await api(`/api/ciphers/${id}`, { method: 'DELETE' }).catch(() => {});
        const { status } = await api(`/api/ciphers/${id}/delete`, { method: 'DELETE' });
        if (status === 204 || status === 200) deleted++;
      }
      return { ok: deleted > 0, detail: `已删除 ${deleted}/${cipherIds.length}` };
    });
  }

  // Delete test folder
  if (testFolderId) {
    await test('DELETE /api/folders/:id 删除测试文件夹', async () => {
      const { status } = await api(`/api/folders/${testFolderId}`, { method: 'DELETE' });
      return { ok: status === 204 || status === 200 };
    });

    await test('文件夹删除后 → 404', async () => {
      const { status } = await api(`/api/folders/${testFolderId}`);
      return { ok: status === 404 };
    });
  }

  // Delete any extra test folders (from import etc.)
  const extraFolderIds = [...new Set(allCreatedFolderIds)];
  if (extraFolderIds.length > 0) {
    await test(`删除导入的测试文件夹 (${extraFolderIds.length} 个)`, async () => {
      let deleted = 0;
      for (const id of extraFolderIds) {
        const { status } = await api(`/api/folders/${id}`, { method: 'DELETE' });
        if (status === 204 || status === 200) deleted++;
      }
      return { ok: true, detail: `已删除 ${deleted}/${extraFolderIds.length}` };
    });
  }

  await test('最终同步一致性检查', async () => {
    const { status, body } = await api('/api/sync');
    if (status !== 200) return { ok: false, detail: `状态码=${status}` };
    return { ok: true, detail: `密码项=${body.ciphers?.length ?? '?'} 文件夹=${body.folders?.length ?? '?'}` };
  });
}

// ─── 18. 缺失端点差距分析 ──────────────────────────────────────────────────
// 列出 Bitwarden 全客户端可能调用但 NodeWarden 尚未实现的端点
// 200=已实现, 501=明确未实现, 404=未路由, 400=端点存在但缺参数, 其他=需关注

async function suiteGapAnalysis() {
  group('18 · 缺失端点差距分析');

  const gaps: [string, string, string][] = [
    ['POST', '/api/two-factor/get-authenticator',    'TOTP 两步验证'],
    ['POST', '/api/two-factor/get-email',            '邮件两步验证'],
    ['POST', '/api/two-factor/get-duo',              'Duo 两步验证'],
    ['POST', '/api/two-factor/get-webauthn',         'WebAuthn 两步验证'],
    ['GET',  '/api/emergency-access/trusted',        '紧急访问（受信任）'],
    ['GET',  '/api/emergency-access/granted',        '紧急访问（已授权）'],
    ['POST', '/api/sends',                           '安全发送（创建）'],
    ['POST', '/api/organizations',                   '组织（创建）'],
    ['GET',  '/api/accounts/billing',                '账单信息'],
    ['GET',  '/api/accounts/subscription',           '订阅信息'],
    ['GET',  '/api/accounts/tax',                    '税务信息'],
    ['POST', '/api/accounts/api-key',                'API 密钥管理'],
    ['POST', '/api/accounts/rotate-api-key',         '轮换 API 密钥'],
    ['POST', '/api/ciphers/purge',                   '清空保管库'],
    ['POST', '/api/ciphers/bulk-delete',             '批量删除'],
    ['POST', '/api/ciphers/restore',                 '批量恢复'],
    ['POST', '/api/folders/delete',                  '批量删除文件夹'],
    ['GET',  '/api/ciphers/organization-details',    '组织密码项详情'],
    ['POST', '/api/accounts/email-token',            '修改邮箱'],
    ['POST', '/api/accounts/verify-email',           '验证邮箱'],
    ['PUT',  '/api/devices/identifier/x/token',      '推送令牌注册'],
    ['DELETE', '/api/push/token',                    '注销推送'],
  ];

  for (const [method, path, label] of gaps) {
    await test(`${method} ${path}（${label}）`, async () => {
      const { status } = await api(path, { method, body: method !== 'GET' && method !== 'DELETE' ? {} : undefined });
      if (status === 200) return { ok: true, detail: '✓ 已实现' };
      if (status === 400) return { ok: true, detail: '✓ 端点存在（缺参数 400）' };
      // 未实现的端点 → 标记为 WARN（黄色），不算 PASS 也不算 FAIL
      if (status === 501) return { warn: true, ok: false, detail: '未实现 (501)' };
      if (status === 404) return { warn: true, ok: false, detail: '未路由 (404)' };
      if (status === 401) return { warn: true, ok: false, detail: '需认证 (401)' };
      return { warn: true, ok: false, detail: `状态码 ${status}` };
    });
  }
}

// ─── 19. 设置页面禁用 ──────────────────────────────────────────────────────

async function suiteSetupDisable() {
  group('19 · 设置页面禁用（单向操作）');

  if (!isNewRegistration) {
    skip('POST /setup/disable', '非全新注册，跳过此破坏性操作');
    skip('GET / 禁用后 → 404', '跳过');
    return;
  }

  await test('POST /setup/disable 禁用设置页面', async () => {
    const { status, body } = await api('/setup/disable', { method: 'POST', auth: false });
    return { ok: status === 200 && body?.success === true };
  });

  await test('GET / 禁用后 → 404', async () => {
    const resp = await fetch(`${BASE}/`);
    return { ok: resp.status === 404 };
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  汇总报告
// ═══════════════════════════════════════════════════════════════════════════

function printSummary(): number {
  const counts = { PASS: 0, FAIL: 0, WARN: 0, SKIP: 0 };
  for (const r of results) counts[r.status]++;
  const total = results.length;
  const totalMs = results.reduce((s, r) => s + r.ms, 0);

  console.log(`\n${c.bold}${c.white}${'═'.repeat(60)}${c.reset}`);
  console.log(`${c.bold}  NodeWarden 自查报告${c.reset}`);
  console.log(`${'═'.repeat(60)}`);
  console.log(`  ${c.green}通过 ${counts.PASS}${c.reset}  │  ${c.red}失败 ${counts.FAIL}${c.reset}  │  ${c.yellow}未实现 ${counts.WARN}${c.reset}  │  ${c.gray}跳过 ${counts.SKIP}${c.reset}  │  总计 ${total}`);
  console.log(`  耗时: ${(totalMs / 1000).toFixed(2)}s`);
  console.log(`${'─'.repeat(60)}`);

  // 失败项
  const failures = results.filter(r => r.status === 'FAIL');
  if (failures.length) {
    console.log(`\n${c.red}${c.bold}  失败项：${c.reset}`);
    for (const f of failures) {
      console.log(`  ${c.red}✘ [${f.group}] ${f.name}${c.reset}`);
      if (f.detail) console.log(`    ${c.dim}${f.detail}${c.reset}`);
    }
  }

  // 未实现项
  const warns = results.filter(r => r.status === 'WARN');
  if (warns.length) {
    console.log(`\n${c.yellow}${c.bold}  尚未实现的功能（${warns.length} 项）：${c.reset}`);
    for (const w of warns) {
      console.log(`  ${c.yellow}⚠ ${w.name}${c.reset}  ${c.dim}${w.detail || ''}${c.reset}`);
    }
  }

  console.log(`\n${c.bold}  分组汇总：${c.reset}`);
  const groups = new Map<string, { pass: number; fail: number; warn: number; total: number }>();
  for (const r of results) {
    if (!groups.has(r.group)) groups.set(r.group, { pass: 0, fail: 0, warn: 0, total: 0 });
    const g = groups.get(r.group)!;
    g.total++;
    if (r.status === 'PASS') g.pass++;
    if (r.status === 'FAIL') g.fail++;
    if (r.status === 'WARN') g.warn++;
  }
  for (const [name, g] of groups) {
    const icon = g.fail > 0 ? `${c.red}✘` : g.warn > 0 ? `${c.yellow}⚠` : `${c.green}✔`;
    const warnStr = g.warn > 0 ? `  ${c.yellow}${g.warn} 未实现${c.reset}` : '';
    console.log(`  ${icon} ${c.reset}${name}  ${c.dim}(${g.pass}/${g.total})${c.reset}${warnStr}`);
  }

  console.log(`\n${'═'.repeat(60)}`);
  if (counts.FAIL === 0 && counts.WARN === 0) {
    console.log(`${c.green}${c.bold}  ✔ 全部检查通过！NodeWarden 兼容全平台 Bitwarden 客户端。${c.reset}`);
  } else if (counts.FAIL === 0) {
    console.log(`${c.green}${c.bold}  ✔ 已实现功能全部通过！${c.reset}${c.yellow}  ⚠ ${counts.WARN} 个端点尚未实现。${c.reset}`);
  } else {
    console.log(`${c.red}${c.bold}  ✘ ${counts.FAIL} 项检查未通过，请查看上方详情。${c.reset}`);
  }
  console.log(`${'═'.repeat(60)}\n`);

  return counts.FAIL;
}

// ═══════════════════════════════════════════════════════════════════════════
//  主流程
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  console.log(`\n${c.bold}${c.cyan}╔${'═'.repeat(58)}╗${c.reset}`);
  console.log(`${c.bold}${c.cyan}║  NodeWarden 自查程序 · Bitwarden API 兼容性全面诊断      ║${c.reset}`);
  console.log(`${c.bold}${c.cyan}╚${'═'.repeat(58)}╝${c.reset}`);
  console.log(`${c.dim}  服务器 : ${BASE}${c.reset}`);
  console.log(`${c.dim}  邮箱   : ${EMAIL}${c.reset}`);
  console.log(`${c.dim}  密码   : ${'*'.repeat(PASSWORD.length)}${c.reset}`);
  console.log(`${c.dim}  时间   : ${new Date().toISOString()}${c.reset}`);

  try { await fetch(`${BASE}/config`); } catch (e: any) {
    console.error(`\n${c.red}  ✘ 无法连接到服务器 ${BASE}${c.reset}`);
    console.error(`${c.dim}    请先启动 NodeWarden: npm run dev${c.reset}`);
    console.error(`${c.dim}    ${e.message}${c.reset}\n`);
    process.exit(1);
  }

  await suiteConnectivity();    //  1. 连通性 + Config 深度
  await suiteCors();            //  2. CORS 深度验证
  await suiteRegistration();    //  3. 注册与设置
  await suiteAuth();            //  4. 认证（多平台 + JWT Claims）
  await suiteRefresh();         //  5. 令牌刷新完整性
  await suiteEmptyVault();      //  6. 空保管库回归测试
  await suiteAccounts();        //  7. 账户端点
  await suiteSync();            //  8. 同步深度验证
  await suiteFolders();         //  9. 文件夹
  await suiteCiphers();         // 10. 密码项
  await suiteAttachments();     // 11. 附件
  await suiteStubs();           // 12. Stub 端点 + 通知
  await suiteIcons();           // 13. 图标代理
  await suiteAuthGuard();       // 14. 认证守卫
  await suiteBlocked();         // 15. 被阻止端点
  await suiteResponseSchema();  // 16. 响应格式合规
  await suiteCleanup();         // 17. 清理
  await suiteGapAnalysis();     // 18. 缺失端点分析
  await suiteSetupDisable();    // 19. 设置页面禁用

  const failCount = printSummary();
  process.exit(failCount > 0 ? 1 : 0);
}

main().catch(e => {
  console.error(`\n${c.red}致命错误: ${e.message || e}${c.reset}\n`);
  process.exit(2);
});
