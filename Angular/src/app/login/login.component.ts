import { Component, OnInit } from '@angular/core';
import { OAuthService } from 'angular-oauth2-oidc';
import { authConfig } from '../auth-config';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
})
export class LoginComponent implements OnInit {

  constructor(private oauthService: OAuthService) {
    
  }

  ngOnInit(): void {
    this.oauthService.configure(authConfig);
   this.oauthService.loadDiscoveryDocument();
  }

  async login() {
    this.oauthService.setupAutomaticSilentRefresh();
    this.oauthService.initCodeFlow();
  }
}
