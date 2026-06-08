import { Injectable, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';

export type Language = 'es' | 'en';

@Injectable({
  providedIn: 'root'
})
export class I18nService {
  private currentLang = signal<Language>('es');
  private translations = signal<Record<string, any>>({});
  private loaded = signal<boolean>(false);

  currentLanguage = this.currentLang.asReadonly();
  isLoaded = this.loaded.asReadonly();

  constructor(private http: HttpClient) {
    this.loadTranslations('es');
  }

  async loadTranslations(lang: Language): Promise<void> {
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
        return key; // Return key if translation not found
      }
    }
    
    return typeof value === 'string' ? value : key;
  }

  // Computed signals for reactive translations
  appTitle = computed(() => this.t('app.title'));
  appSubtitle = computed(() => this.t('app.subtitle'));
}