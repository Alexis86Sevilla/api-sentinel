import { Component, input, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SecurityCardData } from '../../../models/security-report';
import { I18nService } from '../../../services/i18n.service';

@Component({
  selector: 'app-security-card',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './card.html',
})
export class SecurityCard {
  i18n = inject(I18nService);
  report = input.required<SecurityCardData>();
  title = input<string>('Security');

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
      name: this.translateLabel(item.label),
      value: this.translateValue(item.value),
      status: this.mapStatus(item.status),
    }));
  });

  private translationPrefixes = ['header.', 'server.', 'vuln.', 'ssl.', 'cookie.', 'label.'];

  private isTranslationKey(value: string): boolean {
    return this.translationPrefixes.some(prefix => value.startsWith(prefix));
  }

  private translateLabel(label: string): string {
    if (this.isTranslationKey(label)) {
      const translated = this.i18n.t(label);
      return translated !== label ? translated : label;
    }
    return label;
  }

  private translateValue(value: string): string {
    if (this.isTranslationKey(value) && value.includes(':')) {
      const colonIndex = value.indexOf(':');
      const key = value.substring(0, colonIndex);
      const param = value.substring(colonIndex + 1);
      const translated = this.i18n.t(key);
      if (translated !== key) {
        return translated.replace('{{value}}', param);
      }
      return value;
    }

    if (this.isTranslationKey(value)) {
      const translated = this.i18n.t(value);
      return translated !== value ? translated : value;
    }
    return value;
  }

  theme = computed(() => {
    const scoreValue = this.score();
    const key = scoreValue >= 80 ? 'success' : scoreValue >= 50 ? 'warning' : 'error';
    return this.THEMES[key];
  });

  private tooltipKeyMap: Record<string, string> = {
    'strict-transport-security': 'hsts',
    'content-security-policy': 'csp',
    'x-frame-options': 'xFrame',
    'x-content-type-options': 'xContentType',
    'referrer-policy': 'referrer',
    'certificate': 'certificate',
    'protocol': 'protocol',
    'expiration': 'expiration',
    'cipher': 'cipher',
    'secure': 'secure',
    'httponly': 'httpOnly',
    'samesite': 'sameSite',
    'thirdparty': 'thirdParty',
    'server-version': 'serverVersion',
    'clickjacking': 'clickjacking',
    'xss': 'xss',
    'sql-injection': 'sqlInjection',
    'dependencies': 'dependencies',
    'https': 'https',
    'redirect': 'redirect',
    'compression': 'compression',
    'directory-listing': 'directoryListing'
  };

  getTooltip(key: string): { title: string; description: string; fix: string } | null {
    const tooltipKey = this.tooltipKeyMap[key];
    if (!tooltipKey) return null;

    const title = this.i18n.t(`tooltips.${tooltipKey}.title`);
    const description = this.i18n.t(`tooltips.${tooltipKey}.description`);
    const fix = this.i18n.t(`tooltips.${tooltipKey}.fix`);

    if (title === `tooltips.${tooltipKey}.title`) return null;

    return { title, description, fix };
  }
}
