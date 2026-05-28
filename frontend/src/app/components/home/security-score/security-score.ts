import { Component, input, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-security-score',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './security-score.html',
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
