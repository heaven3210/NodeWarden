import { Env, Attachment, DEFAULT_DEV_SECRET } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { createFileDownloadToken, verifyFileDownloadToken } from '../utils/jwt';
import { cipherToResponse } from './ciphers';
import { LIMITS } from '../config/limits';

// Format file size to human readable
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// Get R2 object path for attachment
function getAttachmentPath(cipherId: string, attachmentId: string): string {
  return `${cipherId}/${attachmentId}`;
}

// POST /api/ciphers/{cipherId}/attachment/v2
// Creates attachment metadata and returns upload URL
export async function handleCreateAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  // Verify cipher exists and belongs to user
  const cipher = await storage.getCipher(cipherId);
  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  let body: {
    fileName?: string;
    key?: string;
    fileSize?: number;
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.fileName || !body.key) {
    return errorResponse('fileName and key are required', 400);
  }

  const fileSize = body.fileSize || 0;
  const attachmentId = generateUUID();

  // Create attachment metadata
  const attachment: Attachment = {
    id: attachmentId,
    cipherId: cipherId,
    fileName: body.fileName,
    size: fileSize,
    sizeName: formatSize(fileSize),
    key: body.key,
  };

  // Save attachment metadata
  await storage.saveAttachment(attachment);

  // Add attachment to cipher
  await storage.addAttachmentToCipher(cipherId, attachmentId);

  // Update cipher revision date
  await storage.updateCipherRevisionDate(cipherId);

  // Get updated cipher for response
  const updatedCipher = await storage.getCipher(cipherId);
  const attachments = await storage.getAttachmentsByCipher(cipherId);

  return jsonResponse({
    object: 'attachment-fileUpload',
    attachmentId: attachmentId,
    url: `/api/ciphers/${cipherId}/attachment/${attachmentId}`,
    fileUploadType: 0, // Direct upload
    cipherResponse: cipherToResponse(updatedCipher!, attachments),
  });
}

// Maximum file size: 100MB
const MAX_FILE_SIZE = LIMITS.attachment.maxFileSizeBytes;

// POST /api/ciphers/{cipherId}/attachment/{attachmentId}
// Upload attachment file content
export async function handleUploadAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  // Verify cipher exists and belongs to user
  const cipher = await storage.getCipher(cipherId);
  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  // Check content-length header for size limit
  const contentLength = request.headers.get('content-length');
  if (contentLength && parseInt(contentLength) > MAX_FILE_SIZE) {
    return errorResponse('File too large. Maximum size is 100MB', 413);
  }

  // Get the file from multipart form data
  const contentType = request.headers.get('content-type') || '';
  if (!contentType.includes('multipart/form-data')) {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }

  const formData = await request.formData();
  const file = formData.get('data') as File | null;

  if (!file) {
    return errorResponse('No file uploaded', 400);
  }

  // Check actual file size
  if (file.size > MAX_FILE_SIZE) {
    return errorResponse('File too large. Maximum size is 100MB', 413);
  }

  // Store file in R2
  const path = getAttachmentPath(cipherId, attachmentId);
  await env.ATTACHMENTS.put(path, file.stream(), {
    httpMetadata: {
      contentType: 'application/octet-stream',
    },
    customMetadata: {
      cipherId: cipherId,
      attachmentId: attachmentId,
    },
  });

  // Update attachment size if different
  const actualSize = file.size;
  if (actualSize !== attachment.size) {
    attachment.size = actualSize;
    attachment.sizeName = formatSize(actualSize);
    await storage.saveAttachment(attachment);
  }

  // Update cipher revision date
  await storage.updateCipherRevisionDate(cipherId);

  return new Response(null, { status: 200 });
}

// GET /api/ciphers/{cipherId}/attachment/{attachmentId}
// Get attachment download info
export async function handleGetAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  // Verify cipher exists and belongs to user
  const cipher = await storage.getCipher(cipherId);
  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  // Generate short-lived download token
  const token = await createFileDownloadToken(cipherId, attachmentId, env.JWT_SECRET);
  
  // Generate download URL with token
  const url = new URL(request.url);
  const downloadUrl = `${url.origin}/api/attachments/${cipherId}/${attachmentId}?token=${token}`;

  return jsonResponse({
    object: 'attachment',
    id: attachment.id,
    url: downloadUrl,
    fileName: attachment.fileName,
    key: attachment.key,
    size: Number(attachment.size) || 0,
    sizeName: attachment.sizeName,
  });
}

// GET /api/attachments/{cipherId}/{attachmentId}?token=xxx
// Public download endpoint (uses token for auth instead of header)
export async function handlePublicDownloadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret || secret.length < LIMITS.auth.jwtSecretMinLength || secret === DEFAULT_DEV_SECRET) {
    return errorResponse('Server configuration error', 500);
  }

  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return errorResponse('Token required', 401);
  }

  // Verify token
  const claims = await verifyFileDownloadToken(token, env.JWT_SECRET);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }

  // Verify token matches request
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  // Get file from R2
  const path = getAttachmentPath(cipherId, attachmentId);
  const object = await env.ATTACHMENTS.get(path);

  if (!object) {
    return errorResponse('Attachment file not found', 404);
  }

  const firstUse = await storage.consumeAttachmentDownloadToken(claims.jti, claims.exp);
  if (!firstUse) {
    return errorResponse('Invalid or expired token', 401);
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(object.size),
      'Cache-Control': 'private, no-cache',
    },
  });
}

// DELETE /api/ciphers/{cipherId}/attachment/{attachmentId}
// Delete attachment
export async function handleDeleteAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  // Verify cipher exists and belongs to user
  const cipher = await storage.getCipher(cipherId);
  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  // Delete file from R2
  const path = getAttachmentPath(cipherId, attachmentId);
  await env.ATTACHMENTS.delete(path);

  // Delete attachment metadata
  await storage.deleteAttachment(attachmentId);

  // Remove attachment from cipher
  await storage.removeAttachmentFromCipher(cipherId, attachmentId);

  // Update cipher revision date
  await storage.updateCipherRevisionDate(cipherId);

  // Get updated cipher for response
  const updatedCipher = await storage.getCipher(cipherId);
  const attachments = await storage.getAttachmentsByCipher(cipherId);

  return jsonResponse({
    cipher: cipherToResponse(updatedCipher!, attachments),
  });
}

// Delete all attachments for a cipher (used when deleting cipher)
export async function deleteAllAttachmentsForCipher(
  env: Env,
  cipherId: string
): Promise<void> {
  const storage = new StorageService(env.DB);
  const attachments = await storage.getAttachmentsByCipher(cipherId);

  for (const attachment of attachments) {
    const path = getAttachmentPath(cipherId, attachment.id);
    await env.ATTACHMENTS.delete(path);
    await storage.deleteAttachment(attachment.id);
  }
}
