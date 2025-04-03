import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  issuer: 'https://localhost:44355/',
  redirectUri: 'https://localhost:4200/callback',
  clientId: 'angular-client',
  scope: 'openid profile email offline_access service1 service2',
  responseType: 'code',
  requireHttps: true,
  disablePKCE: false, // PKCE is ENABLED (required for public clients)
};