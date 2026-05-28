import { Component, input, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-security-score',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="w-full max-w-4xl mx-auto mb-8">
      <div class="backdrop-blur-sm rounded-2xl border border-slate-700/50 p-8 shadow-xl"
           [class.bg-emerald-950/20]="isExcellent()"
           [class.bg-blue-950/20]="isGood()"
           [class.bg-amber-950/20]="isRegular()"
           [class.bg-rose-950/20]="isPoor()">
        
        <h2 class="text-center text-xl font-semibold text-slate-300 mb-4">
          Puntuación General
        </h2>
        
        <div class="flex items-baseline justify-center gap-1 mb-4">
          <span class="text-6xl font-bold"
                [class.text-emerald-400]="isExcellent()"
                [class.text-blue-400]="isGood()"
                [class.text-amber-400]="isRegular()"
                [class.text-rose-400]="isPoor()">
            {{ score() }}
          </span>
          <span class="text-2xl text-slate-500">/100</span>
        </div>
        
        <p class="text-center text-lg"
           [class.text-emerald-300]="isExcellent()"
           [class.text-blue-300]="isGood()"
           [class.text-amber-300]="isRegular()"
           [class.text-rose-300]="isPoor()">
          {{ ratingText() }}
        </p>
        
      </div>
    </div>
  `
})
export class SecurityScore {
  score = input.required<number>();

  isExcellent = computed(() => this.score() >= 90);
  isGood = computed(() => this.score() >= 70 && this.score() < 90);
  isRegular = computed(() => this.score() >= 50 && this.score() < 70);
  isPoor = computed(() => this.score() < 50);

  ratingText = computed(() => {
    const s = this.score();
    if (s >= 90) return 'Excelente nivel de seguridad';
    if (s >= 70) return 'Buen nivel de seguridad';
    if (s >= 50) return 'Nivel de seguridad regular';
    return 'Necesita mejoras urgentes';
  });
}