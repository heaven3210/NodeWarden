import { Env } from './types';
import { handleRequest } from './router';
import { StorageService } from './services/storage';
import { applyCors, jsonResponse } from './utils/response';

// Per-isolate flags. Each Worker isolate may have its own copy of these flags.
// initializeDatabase() only validates schema presence, so retries are cheap.
let dbInitialized = false;
let dbInitError: string | null = null;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Auto-initialize database on first request
    if (!dbInitialized) {
      try {
        const storage = new StorageService(env.DB);
        await storage.initializeDatabase();
        dbInitialized = true;
        dbInitError = null;
      } catch (error) {
        console.error('Failed to initialize database:', error);
        dbInitError = error instanceof Error ? error.message : 'Unknown database initialization error';
      }
    }

    if (dbInitError) {
      const resp = jsonResponse(
        {
          error: 'Database not initialized',
          error_description: dbInitError,
          ErrorModel: {
            Message: dbInitError,
            Object: 'error',
          },
        },
        500
      );
      return applyCors(request, resp);
    }

    const resp = await handleRequest(request, env);
    return applyCors(request, resp);
  },
};
