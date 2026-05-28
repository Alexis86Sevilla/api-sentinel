import { inject, Injectable, signal } from '@angular/core';
import { SecurityCardData } from '../models/security-report';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root',
})
export class ApiUrlAudit {
  protected http = inject(HttpClient);
  private _headersReport = signal<SecurityCardData | undefined>(undefined);
  private _sslReport = signal<SecurityCardData | undefined>(undefined);
  private _cookiesReport = signal<SecurityCardData | undefined>(undefined);
  private _vulnerabilitiesReport = signal<SecurityCardData | undefined>(undefined);
  private _serverConfigReport = signal<SecurityCardData | undefined>(undefined);
  headersReport = this._headersReport.asReadonly();
  sslReport = this._sslReport.asReadonly();
  cookiesReport = this._cookiesReport.asReadonly();
  vulnerabilitiesReport = this._vulnerabilitiesReport.asReadonly();
  serverConfigReport = this._serverConfigReport.asReadonly();

  public searchByUrl(url: string): void {
    const urlList = `${environment.apiUrl}/audit/headers?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(urlList).subscribe({
      next: (response) => {
        this._headersReport.set(response);
      },
      error: (error) => {
        console.error(error);
        this._headersReport.set(undefined);
      }
    });
  }

  public getSslInfo(url: string): void {
    const sslUrl = `${environment.apiUrl}/audit/ssl?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(sslUrl).subscribe({
      next: (response) => {
        this._sslReport.set(response);
      },
      error: (error) => {
        console.error(error);
        this._sslReport.set(undefined);
      }
    });
  }

  public getCookiesInfo(url: string): void {
    const cookiesUrl = `${environment.apiUrl}/audit/cookies?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(cookiesUrl).subscribe({
      next: (response) => {
        this._cookiesReport.set(response);
      },
      error: (error) => {
        console.error(error);
        this._cookiesReport.set(undefined);
      }
    });
  }

  public getVulnerabilitiesInfo(url: string): void {
    const vulnUrl = `${environment.apiUrl}/audit/vulnerabilities?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(vulnUrl).subscribe({
      next: (response) => {
        this._vulnerabilitiesReport.set(response);
      },
      error: (error) => {
        console.error(error);
        this._vulnerabilitiesReport.set(undefined);
      }
    });
  }

  public getServerConfigInfo(url: string): void {
    const configUrl = `${environment.apiUrl}/audit/server-config?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(configUrl).subscribe({
      next: (response) => {
        this._serverConfigReport.set(response);
      },
      error: (error) => {
        console.error(error);
        this._serverConfigReport.set(undefined);
      }
    });
  }
}
