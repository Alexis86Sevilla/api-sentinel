import { ChangeDetectionStrategy, Component, computed, effect, inject } from '@angular/core';
import { ApiUrlAudit } from '../../services/api-url-audit';
import { SecurityCard } from './card/card';
import { SecurityScore } from './security-score/security-score';

@Component({
  selector: 'app-home',
  imports: [SecurityCard, SecurityScore],
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

  // Calculate average score from all reports that have data
  overallScore = computed(() => {
    const reports = [
      this.headersReport(),
      this.sslReport(),
      this.cookiesReport(),
      this.vulnerabilitiesReport(),
      this.serverConfigReport(),
    ];

    const validScores = reports
      .filter((r): r is NonNullable<typeof r> => r !== undefined)
      .map((r) => r.score);

    if (validScores.length === 0) return 0;

    const sum = validScores.reduce((acc, score) => acc + score, 0);
    return Math.round(sum / validScores.length);
  });

  // Check if any audit has been performed
  hasResults = computed(() => this.overallScore() > 0);

  constructor() {
    effect(() => {
      console.log('Overall Score:', this.overallScore());
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