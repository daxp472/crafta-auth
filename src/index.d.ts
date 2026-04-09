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
}

export interface PasswordPolicyConfig {
  minLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
  expiryDays?: number;
  minStrength?: number;
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
  limits?: {
    loginMax?: number;
    twoFAMax?: number;
    forgotPasswordMax?: number;
    refreshMax?: number;
  };
  baseUrl?: string;
  emailTemplateDir?: string;
  features?: AuthFeaturesConfig;
  logging?: boolean;
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

export class ApiError extends Error {
  status: number;
  constructor(message: string, status?: number);
}

export function auth(config?: AuthConfig): (app: any) => void;

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