export interface SecurityReport {
    targetUrl: string;
    timestamp: string;
    headers: Record<string, string>;
    issues: string[];
    score: number;
}
