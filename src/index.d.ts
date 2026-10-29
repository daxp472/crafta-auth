export interface CraftaAuthRoutes {
  register?: string;
  login?: string;
  verify?: string;
  forgotPassword?: string;
  resetPassword?: string;
  refreshToken?: string;
  profile?: string;
  twoFactor?: string;
  roles?: string;
  permissions?: string;
  magicLink?: string;
}

export interface PasswordPolicyConfig {
  minLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
  expiryDays?: number;
  minStrength?: number;
  passwordHistory?: number;
}

export interface SmtpConfig {
  host: string;
  port: number;
  auth: {
    user: string;
    pass: string;
  };
  from: string;
}

export interface SocialGoogleConfig {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
}

export interface SocialConfig {
  google?: SocialGoogleConfig | null;
  facebook?: any;
  github?: any;
}

export interface EnvConfig {
  JWT_SECRET: string;
  [key: string]: any;
}

export interface RateLimitConfig {
  loginMax?: number;
  twoFAMax?: number;
  forgotPasswordMax?: number;
  refreshMax?: number;
  registerMax?: number;
  /** Per-route max overrides keyed by route name (e.g. "login", "register", "2fa") */
  [routeName: string]: number | undefined;
}

export interface WebhookConfig {
  url: string;
  events?: string[];
  secret?: string;
}

export interface SessionConfig {
  maxSessions?: number;
  sessionExpiryMs?: number;
  /** Milliseconds before expiry at which the X-Session-Expires-In warning header is emitted. Default: 300000 (5 min). */
  warningThresholdMs?: number;
}

export interface LockoutConfig {
  maxAttempts?: number;
  lockDurationMs?: number;
}

export interface AuthFeaturesConfig {
  emailVerification?: boolean;
  loginAlerts?: boolean;
  securityAttempts?: boolean;
  rateLimit?: boolean;
  auditLogs?: boolean;
  twoFactor?: boolean;
  csrf?: boolean;
}

export interface AuthConfig {
  strategy?: 'jwt';
  fields?: string[];
  routes?: CraftaAuthRoutes;
  mongoUrl?: string;
  maxLoginAttempts?: number;
  emailVerification?: boolean;
  loginAlerts?: boolean;
  passwordPolicy?: PasswordPolicyConfig;
  smtp?: SmtpConfig | null;
  social?: SocialConfig;
  env?: EnvConfig;
  accessTokenExpiry?: string;
  refreshTokenDays?: number;
  enableCSRF?: boolean;
  limits?: RateLimitConfig;
  baseUrl?: string;
  emailTemplateDir?: string;
  features?: AuthFeaturesConfig;
  logging?: boolean;
  webhooks?: WebhookConfig;
  session?: SessionConfig;
  lockout?: LockoutConfig;
}

export class ApiError extends Error {
  code: string;
  status: number;
  details?: any;
  constructor(message: string, code?: string, status?: number, details?: any);
  static unauthorized(message?: string, details?: any): ApiError;
  static forbidden(message?: string, details?: any): ApiError;
  static notFound(message?: string, details?: any): ApiError;
  static validation(message?: string, details?: any): ApiError;
  static badRequest(message?: string, details?: any): ApiError;
  static conflict(message?: string, details?: any): ApiError;
  static tooManyRequests(message?: string, details?: any): ApiError;
  static accountLocked(message?: string, details?: any): ApiError;
  static invalidCredentials(message?: string, details?: any): ApiError;
  static invalidToken(message?: string, details?: any): ApiError;
  static expiredToken(message?: string, details?: any): ApiError;
  static emailNotVerified(message?: string, details?: any): ApiError;
  static twoFactorRequired(message?: string, details?: any): ApiError;
  static twoFactorFailed(message?: string, details?: any): ApiError;
  static passwordPolicy(message?: string, details?: any): ApiError;
  static passwordReuse(message?: string, details?: any): ApiError;
  static smtpDisabled(message?: string, details?: any): ApiError;
  static socialAuthFailed(message?: string, details?: any): ApiError;
  static internal(message?: string, details?: any): ApiError;
  static isApiError(err: unknown): err is ApiError;
  static normalize(err: unknown): ApiError;
}

export interface AuthEvent {
  type: string;
  userId?: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

export interface AuthService {
  register(userData: any): Promise<any>;
  verifyEmail(token: string): Promise<any>;
  login(email: string, password: string, deviceInfo: any): Promise<any>;
  verify2FA(userId: string, code: string): Promise<any>;
  refreshToken(refreshToken: string): Promise<any>;
  forgotPassword(email: string): Promise<any>;
  resetPassword(token: string, newPassword: string): Promise<any>;
  generateBackupCodes(userId: string, mfaService: any): Promise<string[]>;
  updateProfile(userId: string, updates: any): Promise<any>;
  generateTokens(user: any): Promise<{ accessToken: string; refreshToken: string }>;
  logout(userId: string, sessionId: string): Promise<boolean>;
  handleSocialLogin(provider: string, profile: any): Promise<any>;
}

export interface RoleService {
  createRole(roleData: any): Promise<any>;
  getRoleByName(name: string): Promise<any>;
  updateRole(name: string, updates: any): Promise<any>;
  deleteRole(name: string): Promise<void>;
  assignPermissions(roleName: string, permissions: any[]): Promise<any>;
  checkPermission(role: string, resource: string, action: string): Promise<boolean>;
}

export interface AuditService {
  logActivity(data: any): Promise<any>;
  getUserActivity(userId: string, filters?: any): Promise<any[]>;
  getActivityByDateRange(startDate: Date, endDate: Date): Promise<any[]>;
  getFailedLoginAttempts(userId: string, timeWindow: number): Promise<number>;
}

export interface MFAService {
  generateSecret(label: string, issuer?: string): Promise<{ secret: string; qrCode: string }>;
  verifyToken(token: string, secret: string): boolean;
  generateBackupCodes(): Array<{ raw: string; hash: string }>;
  verifyBackupCode(rawCode: string, storedCodes?: any[]): any;
}

export interface PasswordPolicyService {
  validate(password: string, userInfo?: any): { isValid: boolean; errors: string[]; strength: number; strengthScore: number };
  allowsReuse(password: string, passwordHistory: any[], bcrypt: any): Promise<boolean>;
  isExpired(lastChange: Date): boolean;
}

/** Returns a heuristic password strength score from 0 (very weak) to 4 (very strong). */
export function getPasswordStrength(password: string): number;

export function auth(config?: AuthConfig): (app: any) => void;
export function normalizeError(err: unknown): ApiError;

export interface AdaptiveTestCase {
  name: string;
  feature: string;
  run: (cfg: AuthConfig, log: any) => Promise<void>;
}

export function inferFeatureFlags(authConfig?: AuthConfig): Record<string, boolean>;
export function runAdaptiveTests(
  authConfig?: AuthConfig,
  featureFlags?: Record<string, boolean>,
  opts?: { logging?: boolean }
): Promise<boolean>;
export const testCatalog: AdaptiveTestCase[];
