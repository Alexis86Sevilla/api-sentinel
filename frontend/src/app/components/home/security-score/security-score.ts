import { Component, input, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { I18nService } from '../../../services/i18n.service';

@Component({
  selector: 'app-security-score',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './security-score.html',
})
export class SecurityScore {
  i18n = inject(I18nService);
  score = input.required<number>();

  isExcellent = computed(() => this.score() >= 90);
  isGood = computed(() => this.score() >= 70 && this.score() < 90);
  isRegular = computed(() => this.score() >= 50 && this.score() < 70);
  isPoor = computed(() => this.score() < 50);

  ratingText = computed(() => {
    const s = this.score();
    if (s >= 90) return this.i18n.t('overallScore.rating.excellent');
    if (s >= 70) return this.i18n.t('overallScore.rating.good');
    if (s >= 50) return this.i18n.t('overallScore.rating.regular');
    return this.i18n.t('overallScore.rating.poor');
  });
}