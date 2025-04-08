import { Component, OnInit } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { OAuthService } from 'angular-oauth2-oidc';
import { authConfig } from '../auth-config';

@Component({
  selector: 'app-service1',
  templateUrl: './service1.component.html'
})
export class Service1Component implements OnInit {
  message = '';

  constructor(private http: HttpClient, private oauthService: OAuthService) {}

  ngOnInit() {
      this.oauthService.configure(authConfig);
    const token = this.oauthService.getAccessToken();
    
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    this.http.get('https://localhost:44373/api/service1', { headers: headers, responseType: 'text' })
      .subscribe(
        (res) => this.message = res,
        (err) => console.error(err)
      );
  }
}