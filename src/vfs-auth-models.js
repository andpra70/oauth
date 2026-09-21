import mongoose from 'mongoose';

const common = { timestamps: true, versionKey: false };

const userSchema = new mongoose.Schema({
  googleSub: { type: String, required: true, unique: true, index: true },
  email: { type: String, required: true, index: true },
  emailVerified: { type: Boolean, default: false },
  name: String,
  firstName: { type: String, maxlength: 100 },
  lastName: { type: String, maxlength: 100 },
  picture: String,
  note: { type: String, maxlength: 2000, default: '' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  status: { type: String, enum: ['active', 'disabled'], default: 'active' },
  lastSeenAt: Date,
}, common);

const sessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sid: { type: String, required: true, unique: true, index: true },
  familyId: { type: String, required: true, index: true },
  currentJti: String,
  accessExpiresAt: Date,
  lastSeenAt: Date,
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
  revokedAt: Date,
  revokeReason: String,
  userAgent: String,
  ip: String,
}, common);

const refreshSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  sid: { type: String, required: true, index: true },
  familyId: { type: String, required: true, index: true },
  tokenHash: { type: String, required: true, unique: true, index: true },
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
  consumedAt: Date,
  revokedAt: Date,
  replacedByHash: String,
}, common);

const auditSchema = new mongoose.Schema({
  actorUserId: mongoose.Schema.Types.ObjectId,
  action: { type: String, required: true },
  target: String,
  reason: String,
  ip: String,
  userAgent: String,
  result: { type: String, default: 'success' },
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
}, common);

export const VfsUser = mongoose.models.User || mongoose.model('User', userSchema);
export const VfsSession = mongoose.models.Session || mongoose.model('Session', sessionSchema);
export const VfsRefreshToken = mongoose.models.RefreshToken || mongoose.model('RefreshToken', refreshSchema);
export const VfsAudit = mongoose.models.Audit || mongoose.model('Audit', auditSchema);
