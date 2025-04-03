import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule } from '@angular/common/http';
import { OAuthModule } from 'angular-oauth2-oidc';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LoginComponent } from './login/login.component';
import { Service1Component } from './service1/service1.component';
import { Service2Component } from './service2/service2.component';
import { CallbackComponent } from './callback/callback.component';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    Service1Component,
    Service2Component,
    CallbackComponent
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
    OAuthModule.forRoot(), 
    AppRoutingModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }