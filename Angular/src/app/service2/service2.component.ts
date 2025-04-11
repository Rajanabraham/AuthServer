import { Component, OnInit } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { OAuthService } from 'angular-oauth2-oidc';
import { authConfig } from '../auth-config';
@Component({
  selector: 'app-service2',
  templateUrl: './service2.component.html'
})
export class Service2Component implements OnInit {
  message = '';

  constructor(private http: HttpClient, private oauthService: OAuthService) {}

  ngOnInit() {
    this.oauthService.configure(authConfig);
    const token = this.oauthService.getAccessToken();
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    this.http.get('https://localhost:44309/gateway/service2', { headers, responseType: 'text' })
      .subscribe({
        next: (res) => this.message = res,
        error: (err) => console.error(err)
      });
  }
}