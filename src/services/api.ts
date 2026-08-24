// src/services/api.ts

const API_BASE = '/api/v1';

export interface FirewallRule {
  id: string;
  name: string;
  description?: string;
  action: 'ALLOW' | 'DROP' | 'REJECT';
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ANY';
  port: number;
  port_range_end?: number;
  source: string;
  destination: string;
  interface_in?: string;
  interface_out?: string;
  enabled: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface RuleSummary {
  id: string;
  name: string;
  action: string;
  protocol: string;
  port: number;
  source: string;
  destination: string;
  enabled: boolean;
  priority: number;
}

export interface RuleCounter {
  rule_id: string;
  packets: number;
  bytes: number;
}

// Generic request handler with error handling
async function apiRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('auth_token');
  
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: 'same-origin',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ code: 'UNKNOWN', message: 'Unknown error' }));
    throw new ApiError(errorData.code || 'API_ERROR', errorData.message || 'Request failed', response.status);
  }

  if (response.status === 204) {
    return {} as T; // No content
  }

  return response.json();
}

export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// Rule API methods
export const rulesApi = {
  async list(): Promise<RuleSummary[]> {
    return apiRequest<RuleSummary[]>('/rules');
  },

  async get(id: string): Promise<FirewallRule> {
    return apiRequest<FirewallRule>(`/rules/${id}`);
  },

  async create(data: Omit<FirewallRule, 'id' | 'created_at' | 'updated_at'>): Promise<FirewallRule> {
    return apiRequest<FirewallRule>('/rules', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async update(id: string, data: Partial<FirewallRule>): Promise<FirewallRule> {
    return apiRequest<FirewallRule>(`/rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async delete(id: string): Promise<void> {
    return apiRequest<void>(`/rules/${id}`, {
      method: 'DELETE',
    });
  },

  async toggle(id: string, enabled: boolean): Promise<{ enabled: boolean }> {
    return apiRequest<{ enabled: boolean }>(`/rules/${id}/toggle`, {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    });
  },

  async getCounters(id: string): Promise<RuleCounter> {
    return apiRequest<RuleCounter>(`/rules/${id}/counters`);
  },
};

// Health check
export const healthApi = {
  async check(): Promise<{ status: string; uptime: number; version: string }> {
    return apiRequest('/health');
  },
};
