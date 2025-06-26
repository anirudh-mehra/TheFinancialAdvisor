interface User {
  id: string;
  name: string;
  email: string;
  assessmentCompleted?: boolean;
  assessmentData?: any;
}

interface AuthResponse {
  message: string;
  token: string;
  user: User;
}

interface LoginData {
  email: string;
  password: string;
}

interface RegisterData {
  name: string;
  email: string;
  password: string;
}

// Use relative URL for API calls - Vite proxy will handle routing to backend
const API_BASE_URL = '/api';

class AuthService {
  private token: string | null = null;

  constructor() {
    // Load token from localStorage on initialization
    this.token = localStorage.getItem('authToken');
  }

  private async makeRequest(endpoint: string, options: RequestInit = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    
    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...(this.token && { Authorization: `Bearer ${this.token}` }),
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `HTTP error! status: ${response.status}`);
      }

      return data;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Network error occurred');
    }
  }

  async register(userData: RegisterData): Promise<AuthResponse> {
    const response = await this.makeRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });

    // Store token
    this.token = response.token;
    localStorage.setItem('authToken', response.token);

    return response;
  }

  async login(credentials: LoginData): Promise<AuthResponse> {
    const response = await this.makeRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });

    // Store token
    this.token = response.token;
    localStorage.setItem('authToken', response.token);

    return response;
  }

  async getProfile(): Promise<{ user: User }> {
    if (!this.token) {
      throw new Error('No authentication token found');
    }

    return await this.makeRequest('/auth/profile');
  }

  async saveAssessment(assessmentData: any): Promise<{ message: string; assessmentId: number }> {
    if (!this.token) {
      throw new Error('No authentication token found');
    }

    return await this.makeRequest('/assessment', {
      method: 'POST',
      body: JSON.stringify({ assessmentData }),
    });
  }

  async verifyToken(): Promise<boolean> {
    if (!this.token) {
      return false;
    }

    try {
      await this.makeRequest('/auth/verify', {
        method: 'POST',
      });
      return true;
    } catch (error) {
      // Token is invalid, remove it
      this.logout();
      return false;
    }
  }

  logout(): void {
    this.token = null;
    localStorage.removeItem('authToken');
  }

  isAuthenticated(): boolean {
    return !!this.token;
  }

  getToken(): string | null {
    return this.token;
  }
}

export const authService = new AuthService();
export type { User, AuthResponse, LoginData, RegisterData };