import { Env, Folder, FolderResponse } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';

// Convert internal folder to API response format
function folderToResponse(folder: Folder): FolderResponse {
  return {
    id: folder.id,
    name: folder.name,
    revisionDate: folder.updatedAt,
    object: 'folder',
  };
}

// GET /api/folders
export async function handleGetFolders(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const pagination = parsePagination(url);

  let folders: Folder[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await storage.getFoldersPage(userId, pagination.limit + 1, pagination.offset);
    const hasNext = pageRows.length > pagination.limit;
    folders = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + folders.length) : null;
  } else {
    folders = await storage.getAllFolders(userId);
  }

  return jsonResponse({
    data: folders.map(folderToResponse),
    object: 'list',
    continuationToken: continuationToken,
  });
}

// GET /api/folders/:id
export async function handleGetFolder(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const folder = await storage.getFolder(id);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  return jsonResponse(folderToResponse(folder));
}

// POST /api/folders
export async function handleCreateFolder(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { name?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.name) {
    return errorResponse('Name is required', 400);
  }

  const now = new Date().toISOString();
  const folder: Folder = {
    id: generateUUID(),
    userId: userId,
    name: body.name,
    createdAt: now,
    updatedAt: now,
  };

  await storage.saveFolder(folder);
  await storage.updateRevisionDate(userId);

  return jsonResponse(folderToResponse(folder), 200);
}

// PUT /api/folders/:id
export async function handleUpdateFolder(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const folder = await storage.getFolder(id);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  let body: { name?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (body.name) {
    folder.name = body.name;
  }
  folder.updatedAt = new Date().toISOString();

  await storage.saveFolder(folder);
  await storage.updateRevisionDate(userId);

  return jsonResponse(folderToResponse(folder));
}

// DELETE /api/folders/:id
export async function handleDeleteFolder(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const folder = await storage.getFolder(id);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  await storage.clearFolderFromCiphers(userId, id);
  await storage.deleteFolder(id, userId);
  await storage.updateRevisionDate(userId);

  return new Response(null, { status: 204 });
}
