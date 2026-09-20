import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import rateLimit from 'express-rate-limit';
import { OAuth2Client } from 'google-auth-library';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { createClient } from 'redis';
import { VfsAudit, VfsRefreshToken, VfsSession, VfsUser } from './vfs-auth-models.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, '../public/vfs-auth');
const required = (name, fallbackName) => {
  const value = process.env[name] || (fallbackName ? process.env[fallbackName] : '');
  if (!value) throw new Error(`Missing ${name}`);
  return value;
};

export async function createVfsAuthRouter() {
  const callback = required('VFS_GOOGLE_CALLBACK_URL');
  const configuredOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).filter(Boolean);
  const cfg = {
    mongo: required('MONGO_URI'),
    redis: required('REDIS_URL'),
    clientId: required('VFS_GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_ID'),
    clientSecret: required('VFS_GOOGLE_CLIENT_SECRET', 'GOOGLE_CLIENT_SECRET'),
    callback,
    callbacks: new Set((process.env.VFS_GOOGLE_CALLBACK_URLS || callback).split(',').map((value) => value.trim()).filter(Boolean)),
    issuer: process.env.VFS_JWT_ISSUER || process.env.JWT_ISSUER || 'vfs-auth',
    audience: process.env.VFS_JWT_AUDIENCE || process.env.JWT_AUDIENCE || 'vfs-clients',
    accessSeconds: Number(process.env.VFS_ACCESS_TOKEN_SECONDS || process.env.ACCESS_TOKEN_SECONDS || 600),
    refreshSeconds: Number(process.env.VFS_REFRESH_TOKEN_SECONDS || process.env.REFRESH_TOKEN_SECONDS || 2592000),
    cookieSecure: process.env.COOKIE_SECURE !== 'false',
    adminSubs: new Set((process.env.ADMIN_GOOGLE_SUBS || '').split(',').map((value) => value.trim()).filter(Boolean)),
    origins: [...new Set([
      ...configuredOrigins,
      'http://localhost:5173',
      'http://127.0.0.1:5173',
    ])],
  };
  const privateKey = fs.readFileSync(process.env.VFS_PRIVATE_KEY_PATH || process.env.PRIVATE_KEY_PATH || '/run/secrets/private.pem', 'utf8');
  const redis = createClient({ url: cfg.redis });
  redis.on('error', (error) => console.error('[vfs-auth] redis', error.message));
  if (mongoose.connection.readyState === 0) await mongoose.connect(cfg.mongo);
  if (!redis.isOpen) await redis.connect();

  const google = new OAuth2Client(cfg.clientId);
  const router = express.Router();
  const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');
  const random = () => crypto.randomBytes(48).toString('base64url');
  const maskIp = (ip) => String(ip || '').replace(/\d+$/, '0').slice(0, 80);
  const cookieOptions = { httpOnly: true, secure: cfg.cookieSecure, sameSite: 'none', path: '/auth/api', maxAge: cfg.refreshSeconds * 1000 };
  const callbackFor = (req) => {
    const candidate = `${req.protocol}://${req.get('host')}/auth/api/callback`;
    return cfg.callbacks.has(candidate) ? candidate : cfg.callback;
  };
  const safeReturnTo = (value) => {
    const candidate = String(value || '').trim();
    if (candidate.startsWith('/') && !candidate.startsWith('//')) return candidate;
    try {
      const parsed = new URL(candidate);
      return cfg.origins.includes(parsed.origin) ? parsed.toString() : '/example/';
    } catch {
      return '/example/';
    }
  };
  const issueAccess = (user, session) => {
    const jti = crypto.randomUUID();
    const token = jwt.sign({ sub: user.googleSub, sid: session.sid, role: user.role, email: user.email }, privateKey, {
      algorithm: 'RS256', issuer: cfg.issuer, audience: cfg.audience, expiresIn: cfg.accessSeconds, jwtid: jti,
    });
    return { token, jti, expiresAt: new Date(Date.now() + cfg.accessSeconds * 1000) };
  };
  const createRefresh = async (user, session, replacedToken) => {
    const raw = random();
    const tokenHash = sha(raw);
    const expiresAt = new Date(Date.now() + cfg.refreshSeconds * 1000);
    await VfsRefreshToken.create({ userId: user._id, sid: session.sid, familyId: session.familyId, tokenHash, expiresAt });
    if (replacedToken) await VfsRefreshToken.updateOne({ _id: replacedToken._id }, { consumedAt: new Date(), replacedByHash: tokenHash });
    return { raw, tokenHash };
  };
  const revokeSession = async (session, reason) => {
    if (!session || session.revokedAt) return;
    session.revokedAt = new Date();
    session.revokeReason = reason;
    await session.save();
    await VfsRefreshToken.updateMany({ sid: session.sid, revokedAt: null }, { revokedAt: new Date() });
    const ttl = Math.max(1, Math.ceil((session.accessExpiresAt?.getTime() - Date.now()) / 1000));
    await redis.set(`auth:revoked:sid:${session.sid}`, reason, { EX: ttl });
    if (session.currentJti) await redis.set(`auth:revoked:jti:${session.currentJti}`, reason, { EX: ttl });
  };
  const bearer = async (req, res, next) => {
    try {
      const token = req.get('authorization')?.replace(/^Bearer\s+/i, '');
      if (!token) return res.status(401).json({ error: 'missing_token' });
      const decoded = jwt.verify(token, privateKey, { algorithms: ['RS256'], issuer: cfg.issuer, audience: cfg.audience });
      const user = await VfsUser.findOne({ googleSub: decoded.sub });
      const session = await VfsSession.findOne({ sid: decoded.sid });
      if (!user || !session || session.revokedAt) return res.status(401).json({ error: 'session_revoked' });
      req.auth = { decoded, user, session };
      return next();
    } catch {
      return res.status(401).json({ error: 'invalid_token' });
    }
  };
  const admin = [bearer, (req, res, next) => req.auth.user.role === 'admin' ? next() : res.status(403).json({ error: 'admin_required' })];
  const audit = (req, action, target, reason) => VfsAudit.create({ actorUserId: req.auth?.user?._id, action, target, reason, ip: maskIp(req.ip), userAgent: String(req.get('user-agent') || '').slice(0, 200), expiresAt: new Date(Date.now() + 180 * 86400000) });

  router.use(compression(), cookieParser(), express.json({ limit: '64kb' }));
  router.use(cors({ origin(origin, done) { done(null, !origin || cfg.origins.includes(origin)); }, credentials: true }));
  router.use('/api', rateLimit({ windowMs: 60000, limit: 120, standardHeaders: true, legacyHeaders: false }));
  router.get('/healthz', (_req, res) => res.json({ status: 'ok', service: 'vfs-auth' }));
  router.get('/widget.js', (_req, res) => res.sendFile(path.join(publicDir, 'auth-widget.js')));
  router.use('/admin', express.static(path.join(publicDir, 'admin'), { index: 'index.html', maxAge: 0 }));
  router.get('/api/login', (req, res) => {
    const resolvedCallback = callbackFor(req);
    const returnTo = safeReturnTo(req.query.return_to || '/example/');
    const state = random();
    res.cookie('oauth_state', state, { ...cookieOptions, path: '/auth/api/callback', maxAge: 600000 });
    res.cookie('oauth_return_to', returnTo, { ...cookieOptions, path: '/auth/api/callback', maxAge: 600000 });
    const params = new URLSearchParams({ client_id: cfg.clientId, redirect_uri: resolvedCallback, response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account' });
    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  });
  router.get('/api/callback', async (req, res, next) => { try {
    // The public callback is shared with the OIDC Google flow. A state that
    // does not belong to the VFS cookie must be delegated to that handler.
    if (!req.cookies.oauth_state || req.query.state !== req.cookies.oauth_state) return next();
    if (!req.query.code) return res.status(400).send('Invalid OAuth state');
    const resolvedCallback = callbackFor(req);
    const body = new URLSearchParams({ code: String(req.query.code), client_id: cfg.clientId, client_secret: cfg.clientSecret, redirect_uri: resolvedCallback, grant_type: 'authorization_code' });
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    if (!tokenResponse.ok) throw new Error('Google token exchange failed');
    const googleTokens = await tokenResponse.json();
    const ticket = await google.verifyIdToken({ idToken: googleTokens.id_token, audience: cfg.clientId });
    const payload = ticket.getPayload();
    if (!payload?.sub || !payload.email_verified) throw new Error('Invalid Google identity');
    const role = cfg.adminSubs.has(payload.sub) ? 'admin' : 'user';
    const user = await VfsUser.findOneAndUpdate({ googleSub: payload.sub }, { email: payload.email, emailVerified: true, name: payload.name, picture: payload.picture, role, lastSeenAt: new Date() }, { upsert: true, new: true });
    const sid = crypto.randomUUID();
    const familyId = crypto.randomUUID();
    const session = await VfsSession.create({ userId: user._id, sid, familyId, expiresAt: new Date(Date.now() + cfg.refreshSeconds * 1000), lastSeenAt: new Date(), userAgent: String(req.get('user-agent') || '').slice(0, 200), ip: maskIp(req.ip) });
    const refresh = await createRefresh(user, session);
    res.cookie('vfs_refresh', refresh.raw, cookieOptions);
    res.clearCookie('oauth_state', { path: '/auth/api/callback' });
    const returnTo = safeReturnTo(req.cookies.oauth_return_to || '/example/');
    res.clearCookie('oauth_return_to', { path: '/auth/api/callback' });
    const destination = returnTo.startsWith('/') ? `${new URL(resolvedCallback).origin}${returnTo}` : returnTo;
    return res.redirect(destination);
  } catch (error) { return next(error); } });
  router.post('/api/refresh', async (req, res, next) => { try {
    const raw = req.cookies.vfs_refresh;
    if (!raw) return res.status(401).json({ error: 'missing_refresh' });
    const refreshToken = await VfsRefreshToken.findOne({ tokenHash: sha(raw) });
    if (!refreshToken) { res.clearCookie('vfs_refresh', cookieOptions); return res.status(401).json({ error: 'invalid_refresh' }); }
    const session = await VfsSession.findOne({ sid: refreshToken.sid });
    if (refreshToken.consumedAt || refreshToken.revokedAt) { await revokeSession(session, 'refresh_reuse'); res.clearCookie('vfs_refresh', cookieOptions); return res.status(401).json({ error: 'refresh_reuse' }); }
    if (!session || session.revokedAt || refreshToken.expiresAt < new Date()) return res.status(401).json({ error: 'session_expired' });
    const user = await VfsUser.findById(refreshToken.userId);
    if (!user || user.status !== 'active') return res.status(401).json({ error: 'user_disabled' });
    const claim = await VfsRefreshToken.updateOne({ _id: refreshToken._id, consumedAt: null, revokedAt: null }, { consumedAt: new Date() });
    if (claim.modifiedCount !== 1) { await revokeSession(session, 'refresh_reuse'); res.clearCookie('vfs_refresh', cookieOptions); return res.status(401).json({ error: 'refresh_reuse' }); }
    const replacement = await createRefresh(user, session);
    await VfsRefreshToken.updateOne({ _id: refreshToken._id }, { replacedByHash: replacement.tokenHash });
    const access = issueAccess(user, session);
    session.currentJti = access.jti;
    session.accessExpiresAt = access.expiresAt;
    session.lastSeenAt = new Date();
    await session.save();
    res.cookie('vfs_refresh', replacement.raw, cookieOptions);
    return res.json({ accessToken: access.token, expiresAt: access.expiresAt.toISOString(), user: { sub: user.googleSub, email: user.email, name: user.name, picture: user.picture, role: user.role }, issuer: cfg.issuer, audience: cfg.audience });
  } catch (error) { return next(error); } });
  router.post('/api/logout', bearer, async (req, res, next) => { try { await revokeSession(req.auth.session, 'logout'); res.clearCookie('vfs_refresh', cookieOptions).status(204).end(); } catch (error) { next(error); } });
  router.get('/api/session', bearer, (req, res) => res.json({ user: req.auth.user, sid: req.auth.session.sid }));
  router.get('/api/admin/stats', ...admin, async (_req, res) => res.json({ users: await VfsUser.countDocuments(), activeUsers: await VfsUser.countDocuments({ status: 'active' }), activeSessions: await VfsSession.countDocuments({ revokedAt: null, expiresAt: { $gt: new Date() } }), revokedSessions: await VfsSession.countDocuments({ revokedAt: { $ne: null } }) }));
  router.get('/api/admin/users', ...admin, async (req, res) => { const limit = Math.min(100, Number(req.query.limit || 25)); const page = Math.max(1, Number(req.query.page || 1)); const query = req.query.q ? { $or: [{ email: new RegExp(String(req.query.q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') }, { name: new RegExp(String(req.query.q), 'i') }] } : {}; res.json({ items: await VfsUser.find(query).sort({ lastSeenAt: -1 }).skip((page - 1) * limit).limit(limit).lean(), page, limit, total: await VfsUser.countDocuments(query) }); });
  router.get('/api/admin/sessions', ...admin, async (req, res) => { const limit = Math.min(100, Number(req.query.limit || 50)); res.json({ items: await VfsSession.find().populate('userId', 'email name googleSub').sort({ updatedAt: -1 }).limit(limit).lean() }); });
  router.post('/api/admin/sessions/:sid/revoke', ...admin, async (req, res) => { const session = await VfsSession.findOne({ sid: req.params.sid }); if (!session) return res.status(404).json({ error: 'not_found' }); await revokeSession(session, req.body.reason || 'admin'); await audit(req, 'revoke_session', session.sid, req.body.reason); return res.json({ revoked: true }); });
  router.post('/api/admin/users/:id/revoke', ...admin, async (req, res) => { const sessions = await VfsSession.find({ userId: req.params.id, revokedAt: null }); await Promise.all(sessions.map((session) => revokeSession(session, req.body.reason || 'admin_user_revoke'))); await audit(req, 'revoke_user', req.params.id, req.body.reason); res.json({ revoked: sessions.length }); });
  router.get('/api/admin/audit', ...admin, async (_req, res) => res.json({ items: await VfsAudit.find().sort({ createdAt: -1 }).limit(100).lean() }));
  router.use((error, _req, res, _next) => {
    console.error('[vfs-auth]', error);
    if (!res.headersSent) res.status(500).json({ error: 'internal_error' });
  });
  return router;
}
