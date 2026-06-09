import { Injectable, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import esTranslations from '../../assets/i18n/es.json';

export type Language = 'es' | 'en';

@Injectable({
  providedIn: 'root'
})
export class I18nService {
  private currentLang = signal<Language>('es');
  private translations = signal<Record<string, any>>(esTranslations);
  private loaded = signal<boolean>(true);

  currentLanguage = this.currentLang.asReadonly();
  isLoaded = this.loaded.asReadonly();

  constructor(private http: HttpClient) {}

  async loadTranslations(lang: Language): Promise<void> {
    if (lang === 'es') {
      this.translations.set(esTranslations);
      this.currentLang.set('es');
      this.loaded.set(true);
      return;
    }

    try {
      const data = await this.http.get<Record<string, any>>(`/assets/i18n/${lang}.json`).toPromise();
      if (data) {
        this.translations.set(data);
        this.currentLang.set(lang);
        this.loaded.set(true);
      }
    } catch (error) {
      console.error(`Error loading translations for ${lang}:`, error);
    }
  }

  setLanguage(lang: Language): void {
    if (lang !== this.currentLang()) {
      this.loadTranslations(lang);
    }
  }

  t(key: string): string {
    const keys = key.split('.');
    let value: any = this.translations();

    for (const k of keys) {
      if (value && typeof value === 'object' && k in value) {
        value = value[k];
      } else {
        return key;
      }
    }

    return typeof value === 'string' ? value : key;
  }

  appTitle = computed(() => this.t('app.title'));
  appSubtitle = computed(() => this.t('app.subtitle'));
}