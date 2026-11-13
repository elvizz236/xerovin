import 'dotenv/config';
import express, { type Request, type Response, type NextFunction } from 'express';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { GoogleGenAI, ThinkingLevel } from '@google/genai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const STORE_PATH = path.join(os.tmpdir(), 'xerovin-workspace-store.json');
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update(process.env.GEMINI_API_KEY || 'xerovin-local-secret').digest('hex');

type StudioMode = 'chat' | 'architect' | 'reason' | 'synthesize';
type ReasoningDepth = 'low' | 'medium' | 'high' | 'xhigh';

interface StoredUser {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  salt: string;
  createdAt: string;
}

interface StoredMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  imageDataUrl?: string;
  mode?: StudioMode;
  depth?: ReasoningDepth;
  firstTokenMs?: number;
  totalMs?: number;
  createdAt: string;
}

interface StoredThread {
  id: string;
  userId: string;
  title: string;
  mode: StudioMode;
  depth: ReasoningDepth;
  messages: StoredMessage[];
  createdAt: string;
  updatedAt: string;
}

interface StoreData {
  users: StoredUser[];
  threads: StoredThread[];
}

function readStore(): StoreData {
  try {
    if (fs.existsSync(STORE_PATH)) {
      const raw = fs.readFileSync(STORE_PATH, 'utf8');
      const parsed = JSON.parse(raw) as Partial<StoreData>;
      return {
        users: Array.isArray(parsed.users) ? parsed.users : [],
        threads: Array.isArray(parsed.threads) ? parsed.threads : [],
      };
    }
  } catch {
    // fallback to clean store
  }
  return { users: [], threads: [] };
}

function writeStore(data: StoreData): void {
  fs.writeFileSync(STORE_PATH, JSON.stringify(data, null, 2), 'utf8');
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashPassword(password, salt), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

function signSessionToken(userId: string): string {
  const payload = Buffer.from(
    JSON.stringify({
      uid: userId,
      exp: Date.now() + 1000 * 60 * 60 * 24 * 30, // 30 days
    }),
    'utf8'
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifySessionToken(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      uid?: string;
      exp?: number;
    };
    if (!parsed.uid || !parsed.exp || parsed.exp < Date.now()) {
      return null;
    }
    return parsed.uid;
  } catch {
    return null;
  }
}

function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const cookies = cookieHeader.split(';');
    for (const entry of cookies) {
      const [key, ...rest] = entry.trim().split('=');
      if (key === 'xerovin_token') {
        return decodeURIComponent(rest.join('='));
      }
    }
  }
  return null;
}

interface AuthenticatedRequest extends Request {
  authUser?: StoredUser;
}

function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const token = extractToken(req);
  if (!token) {
    res.status(401).json({ error: 'Please sign in or create an account to send messages.' });
    return;
  }
  const userId = verifySessionToken(token);
  if (!userId) {
    res.status(401).json({ error: 'Session expired. Please sign in again.' });
    return;
  }
  const store = readStore();
  const user = store.users.find((u) => u.id === userId);
  if (!user) {
    res.status(401).json({ error: 'Account not found. Please sign in again.' });
    return;
  }
  req.authUser = user;
  next();
}

const SYSTEM_INSTRUCTIONS: Record<StudioMode, string> = {
  chat:
    'You are XEROVIN, a sharp, clear, and highly capable AI assistant. Provide direct, well-structured, accurate answers using clean Markdown formatting.',
  architect:
    'You are XEROVIN Architect, a senior systems and software engineer. Deliver clean, production-grade TypeScript, system architectures, and API contracts with concise technical explanations and fenced code blocks.',
  reason:
    'You are XEROVIN Deep Reason, an analytical reasoning engine. Decompose complex engineering, mathematical, and strategic problems step-by-step, verify edge cases, and finish with a concrete conclusion.',
  synthesize:
    'You are XEROVIN Synthesize, an intelligence compiler. Transform messy notes, transcripts, or specifications into structured summaries, priority tables, and deterministic JSON schemas.',
};

function mapThinkingLevel(depth: ReasoningDepth | undefined): ThinkingLevel {
  switch (depth) {
    case 'low':
      return ThinkingLevel.LOW;
    case 'medium':
      return ThinkingLevel.MEDIUM;
    case 'xhigh':
      return ThinkingLevel.XHIGH;
    case 'high':
    default:
      return ThinkingLevel.HIGH;
  }
}

function getGenAIClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

function sanitizeUser(user: StoredUser) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt,
  };
}

function deriveTitle(prompt: string): string {
  const cleaned = prompt.replace(/\s+/g, ' ').trim();
  if (!cleaned) return 'Visual Inspection';
  return cleaned.length > 48 ? `${cleaned.slice(0, 48).trimEnd()}...` : cleaned;
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '12mb' }));

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ ok: true, service: 'xerovin-kimi-workspace' });
  });

  // Register new account
  app.post('/api/auth/register', (req: Request, res: Response) => {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (name.length < 2) {
      res.status(400).json({ error: 'Please enter your name (at least 2 characters).' });
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }
    if (password.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters.' });
      return;
    }

    const store = readStore();
    if (store.users.some((u) => u.email === email)) {
      res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });
      return;
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const newUser: StoredUser = {
      id: crypto.randomUUID(),
      name,
      email,
      salt,
      passwordHash: hashPassword(password, salt),
      createdAt: new Date().toISOString(),
    };

    store.users.push(newUser);
    writeStore(store);

    const token = signSessionToken(newUser.id);
    res.json({
      token,
      user: sanitizeUser(newUser),
    });
  });

  // Sign in existing account
  app.post('/api/auth/login', (req: Request, res: Response) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!email || !password) {
      res.status(400).json({ error: 'Email and password are required.' });
      return;
    }

    const store = readStore();
    const user = store.users.find((u) => u.email === email);
    if (!user || !verifyPassword(password, user.salt, user.passwordHash)) {
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    const token = signSessionToken(user.id);
    res.json({
      token,
      user: sanitizeUser(user),
    });
  });

  // Check current session
  app.get('/api/auth/me', (req: Request, res: Response) => {
    const token = extractToken(req);
    if (!token) {
      res.json({ user: null });
      return;
    }
    const userId = verifySessionToken(token);
    if (!userId) {
      res.json({ user: null });
      return;
    }
    const store = readStore();
    const user = store.users.find((u) => u.id === userId);
    res.json({ user: user ? sanitizeUser(user) : null });
  });

  // List authenticated user's threads
  app.get('/api/threads', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const user = req.authUser!;
    const store = readStore();
    const threads = store.threads
      .filter((t) => t.userId === user.id)
      .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
    res.json({ threads });
  });

  // Delete a thread
  app.delete('/api/threads/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const user = req.authUser!;
    const threadId = req.params.id;
    const store = readStore();
    const nextThreads = store.threads.filter(
      (t) => !(t.id === threadId && t.userId === user.id)
    );
    if (nextThreads.length === store.threads.length) {
      res.status(404).json({ error: 'Thread not found.' });
      return;
    }
    store.threads = nextThreads;
    writeStore(store);
    res.json({ deleted: true });
  });

  // Stream AI response (strictly protected by requireAuth)
  app.post('/api/ai/stream', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    const user = req.authUser!;
    const body = (req.body || {}) as {
      threadId?: string;
      mode?: StudioMode;
      depth?: ReasoningDepth;
      prompt?: string;
      imageBase64?: string;
      imageMimeType?: string;
    };

    const mode: StudioMode = body.mode && body.mode in SYSTEM_INSTRUCTIONS ? body.mode : 'chat';
    const depth: ReasoningDepth = body.depth || 'medium';
    const prompt = typeof body.prompt === 'string' ? body.prompt.trim() : '';

    if (!prompt && !body.imageBase64) {
      res.status(400).json({ error: 'Prompt or image attachment is required.' });
      return;
    }

    const ai = getGenAIClient();
    if (!ai) {
      res.status(503).json({
        error:
          'Server Gemini API key is not configured. Open Settings > Secrets in AI Studio to attach GEMINI_API_KEY.',
      });
      return;
    }

    const store = readStore();
    const nowIso = new Date().toISOString();
    let thread = body.threadId
      ? store.threads.find((t) => t.id === body.threadId && t.userId === user.id)
      : undefined;

    if (!thread) {
      thread = {
        id: crypto.randomUUID(),
        userId: user.id,
        title: deriveTitle(prompt),
        mode,
        depth,
        messages: [],
        createdAt: nowIso,
        updatedAt: nowIso,
      };
      store.threads.push(thread);
    } else {
      thread.mode = mode;
      thread.depth = depth;
      thread.updatedAt = nowIso;
    }

    const userMsg: StoredMessage = {
      id: crypto.randomUUID(),
      role: 'user',
      content: prompt || 'Inspect the attached image.',
      imageDataUrl:
        body.imageBase64 && body.imageMimeType
          ? `data:${body.imageMimeType};base64,${body.imageBase64}`
          : undefined,
      mode,
      depth,
      createdAt: nowIso,
    };

    // Build conversational history for multi-turn continuity
    const historyContents = thread.messages.slice(-12).map((m) => ({
      role: m.role === 'assistant' ? ('model' as const) : ('user' as const),
      parts: [{ text: m.content }],
    }));

    const currentParts: Array<
      { text: string } | { inlineData: { mimeType: string; data: string } }
    > = [];

    if (body.imageBase64 && body.imageMimeType) {
      currentParts.push({
        inlineData: {
          mimeType: body.imageMimeType,
          data: body.imageBase64,
        },
      });
    }
    currentParts.push({
      text: prompt || 'Inspect this visual artifact and summarize key observations.',
    });

    const contents = [
      ...historyContents,
      {
        role: 'user' as const,
        parts: currentParts,
      },
    ];

    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    let closed = false;
    req.on('close', () => {
      closed = true;
    });

    const writeEvent = (payload: Record<string, unknown>) => {
      if (!closed) {
        res.write(`data: ${JSON.stringify(payload)}\n\n`);
      }
    };

    writeEvent({
      type: 'meta',
      threadId: thread.id,
      threadTitle: thread.title,
      userMessageId: userMsg.id,
    });

    const startedAt = Date.now();
    let firstTokenMs: number | null = null;
    let assistantText = '';

    try {
      const stream = await ai.models.generateContentStream({
        model: 'gemini-4-hydrogen',
        contents,
        config: {
          systemInstruction: SYSTEM_INSTRUCTIONS[mode],
          thinkingConfig: {
            thinkingLevel: mapThinkingLevel(depth),
          },
        },
      });

      for await (const chunk of stream) {
        if (closed) break;
        const text = chunk.text ?? '';
        if (text) {
          if (firstTokenMs === null) {
            firstTokenMs = Date.now() - startedAt;
          }
          assistantText += text;
          writeEvent({ type: 'chunk', text, firstTokenMs });
        }
      }

      const totalMs = Date.now() - startedAt;
      const assistantMsg: StoredMessage = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: assistantText,
        mode,
        depth,
        firstTokenMs: firstTokenMs ?? totalMs,
        totalMs,
        createdAt: new Date().toISOString(),
      };

      thread.messages.push(userMsg, assistantMsg);
      thread.updatedAt = new Date().toISOString();
      writeStore(store);

      writeEvent({
        type: 'done',
        threadId: thread.id,
        assistantMessageId: assistantMsg.id,
        firstTokenMs: assistantMsg.firstTokenMs,
        totalMs,
      });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Unexpected inference error while streaming response.';
      writeEvent({ type: 'error', message });
    } finally {
      if (!closed) {
        res.end();
      }
    }
  });

  if (!IS_PRODUCTION) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req: Request, res: Response) => {
      const indexHtml = path.join(distDir, 'index.html');
      if (fs.existsSync(indexHtml)) {
        res.sendFile(indexHtml);
      } else {
        res.status(404).send('Build output not found. Run npm run build first.');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`XEROVIN workspace server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start XEROVIN server:', err);
  process.exit(1);
});
