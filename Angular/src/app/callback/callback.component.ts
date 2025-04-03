import { Component, OnInit } from '@angular/core';
import { OAuthService } from 'angular-oauth2-oidc';
import { Router } from '@angular/router';
import { authConfig } from '../auth-config';

@Component({
  selector: 'app-callback',
  template: '<p>Completing authentication...</p>',
})
export class CallbackComponent implements OnInit {
  constructor(
    private oauthService: OAuthService,
    private router: Router
  ) {}

  async ngOnInit() {
    try {
      this.oauthService.configure(authConfig);
      // Ensure the discovery document is loaded (if used)
      await this.oauthService.loadDiscoveryDocument();

      // Trigger the token exchange
      await this.oauthService.tryLogin();

      // Check if we got a valid access token
      if (this.oauthService.hasValidAccessToken()) {
        localStorage.setItem('accesstoken',this.oauthService.getAccessToken())
        // Optionally load user profile
       // await this.oauthService.loadUserProfile();
        this.router.navigate(['/service1']);
      } else {
        throw new Error('No valid access token received');
      }
    } catch (error) {
      console.error('Authentication failed:', error);
      this.router.navigate(['/login'], {
        state: { error: 'Authentication failed' },
      });
    }
  }
}