export const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

export async function apiRequest<T>(url: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(url.startsWith('http') ? url : `${API_BASE_URL}${url}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    const text = await response.text();
    try {
      const data = JSON.parse(text);
      throw new Error(data.detail || data.message || response.statusText);
    } catch (error) {
      if (error instanceof Error && error.message !== response.statusText) throw error;
      throw new Error(response.statusText);
    }
  }

  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
