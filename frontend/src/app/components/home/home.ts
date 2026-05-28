import { ChangeDetectionStrategy, Component, effect, inject } from '@angular/core';
import { ApiUrlAudit } from '../../services/api-url-audit';
import { SecurityCard } from './card/card';

@Component({
  selector: 'app-home',
  imports: [SecurityCard],
  templateUrl: './home.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Home {
  private apiService = inject(ApiUrlAudit);
  protected headersReport = this.apiService.headersReport;
  protected sslReport = this.apiService.sslReport;
  protected cookiesReport = this.apiService.cookiesReport;
  protected vulnerabilitiesReport = this.apiService.vulnerabilitiesReport;
  protected serverConfigReport = this.apiService.serverConfigReport;

  constructor() {
    effect(() => {
      console.log('Headers:', this.headersReport());
      console.log('SSL:', this.sslReport());
      console.log('Cookies:', this.cookiesReport());
      console.log('Vulnerabilities:', this.vulnerabilitiesReport());
      console.log('Server Config:', this.serverConfigReport());
    });
  }

  public onSearchByUrl(url: string): void {
    this.apiService.searchByUrl(url);
    this.apiService.getSslInfo(url);
    this.apiService.getCookiesInfo(url);
    this.apiService.getVulnerabilitiesInfo(url);
    this.apiService.getServerConfigInfo(url);
  }
}