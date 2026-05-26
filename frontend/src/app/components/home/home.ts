import { ChangeDetectionStrategy, Component, effect, inject } from '@angular/core';
import { ApiUrlAudit } from '../../services/api-url-audit';

@Component({
  selector: 'app-home',
  imports: [],
  templateUrl: './home.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Home {
  private apiService = inject(ApiUrlAudit);
  protected urlAnalytics = this.apiService.urlAnalyzed;

  constructor() {
    effect(() => {
      console.warn(this.urlAnalytics());
    });
  }

  public onSearchByUrl(url: string): void {
    this.apiService.searchByUrl(url);
  }
}
