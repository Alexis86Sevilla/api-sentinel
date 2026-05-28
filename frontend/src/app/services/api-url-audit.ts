import { inject, Injectable, signal } from '@angular/core';
import { SecurityCardData } from '../models/security-report';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root',
})
export class ApiUrlAudit {
  protected http = inject(HttpClient);
  private _isLoading = signal<boolean>(false);
  private _headersReport = signal<SecurityCardData | undefined>(undefined);
  private _sslReport = signal<SecurityCardData | undefined>(undefined);
  private _cookiesReport = signal<SecurityCardData | undefined>(undefined);
  private _vulnerabilitiesReport = signal<SecurityCardData | undefined>(undefined);
  private _serverConfigReport = signal<SecurityCardData | undefined>(undefined);

  isLoading = this._isLoading.asReadonly();
  headersReport = this._headersReport.asReadonly();
  sslReport = this._sslReport.asReadonly();
  cookiesReport = this._cookiesReport.asReadonly();
  vulnerabilitiesReport = this._vulnerabilitiesReport.asReadonly();
  serverConfigReport = this._serverConfigReport.asReadonly();

  public searchAll(url: string): void {
    this._isLoading.set(true);
    this._headersReport.set(undefined);
    this._sslReport.set(undefined);
    this._cookiesReport.set(undefined);
    this._vulnerabilitiesReport.set(undefined);
    this._serverConfigReport.set(undefined);

    let completedCount = 0;
    const totalRequests = 5;

    const checkComplete = () => {
      completedCount++;
      if (completedCount >= totalRequests) {
        this._isLoading.set(false);
      }
    };


    const headersUrl = `${environment.apiUrl}/audit/headers?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(headersUrl).subscribe({
      next: (response) => {
        this._headersReport.set(response);
      },
      error: (error) => {
        console.error('Headers error:', error);
        this._headersReport.set({ score: 0, items: [] });
      },
      complete: checkComplete
    });


    const sslUrl = `${environment.apiUrl}/audit/ssl?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(sslUrl).subscribe({
      next: (response) => {
        this._sslReport.set(response);
      },
      error: (error) => {
        console.error('SSL error:', error);
        this._sslReport.set({ score: 0, items: [] });
      },
      complete: checkComplete
    });


    const cookiesUrl = `${environment.apiUrl}/audit/cookies?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(cookiesUrl).subscribe({
      next: (response) => {
        this._cookiesReport.set(response);
      },
      error: (error) => {
        console.error('Cookies error:', error);
        this._cookiesReport.set({ score: 0, items: [] });
      },
      complete: checkComplete
    });


    const vulnUrl = `${environment.apiUrl}/audit/vulnerabilities?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(vulnUrl).subscribe({
      next: (response) => {
        this._vulnerabilitiesReport.set(response);
      },
      error: (error) => {
        console.error('Vulnerabilities error:', error);
        this._vulnerabilitiesReport.set({ score: 0, items: [] });
      },
      complete: checkComplete
    });

    const configUrl = `${environment.apiUrl}/audit/server-config?url=${encodeURIComponent(url)}`;
    this.http.get<SecurityCardData>(configUrl).subscribe({
      next: (response) => {
        this._serverConfigReport.set(response);
      },
      error: (error) => {
        console.error('Server config error:', error);
        this._serverConfigReport.set({ score: 0, items: [] });
      },
      complete: checkComplete
    });
  }

  public searchByUrl(url: string): void {
    this.searchAll(url);
  }
}
