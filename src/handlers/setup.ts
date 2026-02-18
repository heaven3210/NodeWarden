import { Env, DEFAULT_DEV_SECRET } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse, htmlResponse } from '../utils/response';
import { renderRegisterPageHTML } from '../setup/pageTemplate';
import { LIMITS } from '../config/limits';

type JwtSecretState = 'missing' | 'default' | 'too_short';

function getJwtSecretState(env: Env): JwtSecretState | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  // Block common "forgot to change" sample value (matches .dev.vars.example)
  if (secret === DEFAULT_DEV_SECRET) return 'default';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

async function handleRegisterPage(request: Request, env: Env, jwtState: JwtSecretState | null): Promise<Response> {
  const storage = new StorageService(env.DB);
  const disabled = await storage.isSetupDisabled();
  if (disabled) {
    return new Response(null, { status: 404 });
  }
  return htmlResponse(renderRegisterPageHTML(jwtState));
}

// GET / - Setup page
export async function handleSetupPage(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const disabled = await storage.isSetupDisabled();
  if (disabled) {
    return new Response(null, { status: 404 });
  }

  // 引导页内会处理 JWT_SECRET 检测与分流（坏密钥停留在修复步骤）。
  const jwtState = getJwtSecretState(env);
  return handleRegisterPage(request, env, jwtState);
}

// GET /setup/status
export async function handleSetupStatus(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const registered = await storage.isRegistered();
  const disabled = await storage.isSetupDisabled();
  return jsonResponse({ registered, disabled });
}

// POST /setup/disable
export async function handleDisableSetup(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const registered = await storage.isRegistered();
  if (!registered) {
    return errorResponse('Registration required', 403);
  }
  await storage.setSetupDisabled();
  return jsonResponse({ success: true });
}
