import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { I18nService } from '../../services/i18n.service';

@Component({
  selector: 'app-language-selector',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './language-selector.html'
})
export class LanguageSelector {
  i18n = inject(I18nService);
  currentLang = this.i18n.currentLanguage;

  setLanguage(lang: 'es' | 'en'): void {
    this.i18n.setLanguage(lang);
  }
}