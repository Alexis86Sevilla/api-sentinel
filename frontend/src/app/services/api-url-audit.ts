import { inject, Injectable, signal } from '@angular/core';
import { SecurityReport } from '../models/security-report';
import { HttpClient, HttpResponse } from '@angular/common/http';
import { environment } from '../../environments/environment';

export type EntityResponseType = HttpResponse<SecurityReport>;


@Injectable({
  providedIn: 'root',
})
export class ApiUrlAudit {
  protected http = inject(HttpClient);
  private _urlAnalyzed = signal<SecurityReport | undefined>(undefined);
  urlAnalyzed = this._urlAnalyzed.asReadonly();

  public searchByUrl(url: string): void {
const urlList = `${environment.apiUrl}/audit/headers?url=${encodeURIComponent(url)}`;    this.http.get<SecurityReport>(urlList, { observe: 'response' }).subscribe({
      next: (response) => {
        this._urlAnalyzed.set(response.body || undefined);
      },
      error: (error) => {
        console.error(error);
        this._urlAnalyzed.set(undefined);
      }
    });
  }
}
