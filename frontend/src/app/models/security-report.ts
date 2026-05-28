export interface SecurityCardData {
  score: number;
  items: SecurityItem[];
}

export interface SecurityItem {
  key: string;
  label: string;
  value: string;
  status: string;
}