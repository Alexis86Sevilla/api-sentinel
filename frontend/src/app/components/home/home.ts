import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ApiUrlAudit } from '../../services/api-url-audit';
import { SecurityCard } from './card/card';
import { SecurityScore } from './security-score/security-score';
import { LoadingSpinner } from './loading-spinner/loading-spinner';

@Component({
  selector: 'app-home',
  imports: [SecurityCard, SecurityScore, LoadingSpinner],
  templateUrl: './home.html',
  styleUrl: './home.css',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Home {
  private apiService = inject(ApiUrlAudit);

  protected headersReport = this.apiService.headersReport;
  protected sslReport = this.apiService.sslReport;
  protected cookiesReport = this.apiService.cookiesReport;
  protected vulnerabilitiesReport = this.apiService.vulnerabilitiesReport;
  protected serverConfigReport = this.apiService.serverConfigReport;
  protected isLoading = this.apiService.isLoading;

  // Input validation
  inputUrl = signal('');
  inputTouched = signal(false);

  private urlPattern = /^(https?:\/\/)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/;

  isValidUrl = computed(() => {
    const url = this.inputUrl().trim();
    return url.length > 0 && this.urlPattern.test(url);
  });

  showValidation = computed(() => this.inputTouched() && this.inputUrl().length > 0);

  inputClass = computed(() => {
    if (!this.showValidation()) return '';
    return this.isValidUrl() ? 'valid' : 'invalid';
  });

  allReportsReady = computed(() => {
    return !this.isLoading() &&
           this.headersReport() !== undefined &&
           this.sslReport() !== undefined &&
           this.cookiesReport() !== undefined &&
           this.vulnerabilitiesReport() !== undefined &&
           this.serverConfigReport() !== undefined;
  });

  overallScore = computed(() => {
    if (!this.allReportsReady()) return 0;

    const reports = [
      this.headersReport()!,
      this.sslReport()!,
      this.cookiesReport()!,
      this.vulnerabilitiesReport()!,
      this.serverConfigReport()!,
    ];

    const sum = reports.reduce((acc, r) => acc + r.score, 0);
    return Math.round(sum / reports.length);
  });

  onInputChange(value: string): void {
    this.inputUrl.set(value);
    if (!this.inputTouched()) {
      this.inputTouched.set(true);
    }
  }

  onSearchByUrl(url: string): void {
    if (!url.trim() || !this.isValidUrl()) return;
    this.apiService.searchAll(url.trim());
  }
}
