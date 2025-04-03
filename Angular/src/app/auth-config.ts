import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  issuer: 'https://localhost:44355/',
  redirectUri: 'https://localhost:4200/callback',
  clientId: 'angular-client',
  scope: 'openid profile email service1 service2',
  responseType: 'code',
  showDebugInformation: true,
  requireHttps: true,
  strictDiscoveryDocumentValidation: false,
  clearHashAfterLogin: true, // Clean URL after auth
  disablePKCE: false, // PKCE is ENABLED (required for public clients)
};