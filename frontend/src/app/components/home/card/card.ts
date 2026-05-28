import { Component, input, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SecurityCardData } from '../../../models/security-report';
import { SecurityTooltips } from '../../../data/security-tooltips';

@Component({
  selector: 'app-security-card',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './card.html',
})
export class SecurityCard {
  report = input.required<SecurityCardData>();
  title = input<string>('Seguridad');
  
  THEMES: Record<string, { border: string; scoreColor: string; bg: string; type: string }> = {
    success: { border: 'border-emerald-500/20', scoreColor: 'text-emerald-400', bg: 'bg-emerald-950/10', type: 'success' },
    warning: { border: 'border-amber-500/20',   scoreColor: 'text-amber-400',   bg: 'bg-amber-950/10',   type: 'warning' },
    error:   { border: 'border-rose-500/20',    scoreColor: 'text-rose-400',    bg: 'bg-rose-950/10',    type: 'error' },
  };

  private mapStatus(backendStatus: string): 'success' | 'warning' | 'error' {
    switch (backendStatus) {
      case 'valid':
      case 'success':
        return 'success';
      case 'warning':
        return 'warning';
      case 'invalid':
      case 'error':
        return 'error';
      default:
        return 'error';
    }
  }

  score = computed(() => this.report().score ?? 0);

  items = computed(() => {
    const report = this.report();
    if (!report?.items) {
      return [];
    }

    return report.items.map(item => ({
      key: item.key,
      name: item.label,
      value: item.value,
      status: this.mapStatus(item.status),
    }));
  });

  theme = computed(() => {
    const scoreValue = this.score();
    const key = scoreValue >= 80 ? 'success' : scoreValue >= 50 ? 'warning' : 'error';
    return this.THEMES[key];
  });

  getTooltip(key: string): { title: string; description: string; fix: string } | null {
    return SecurityTooltips[key] || null;
  }
}