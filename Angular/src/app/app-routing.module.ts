import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './login/login.component';
import { Service1Component } from './service1/service1.component';
import { Service2Component } from './service2/service2.component';
import { CallbackComponent } from './callback/callback.component';

const routes: Routes = [
  { path: '', redirectTo: '/login', pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'callback', component: CallbackComponent },
  { path: 'service1', component: Service1Component },
  { path: 'service2', component: Service2Component }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }