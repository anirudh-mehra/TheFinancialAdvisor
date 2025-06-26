import { useState, useEffect, useCallback } from 'react';
import { authService, User } from '../services/auth';

interface UseAuthReturn {
  user: User | null;
  loading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  saveAssessment: (assessmentData: any) => Promise<void>;
  clearError: () => void;
}

export const useAuth = (): UseAuthReturn => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const loadUser = useCallback(async () => {
    try {
      setLoading(true);
      
      if (!authService.isAuthenticated()) {
        setUser(null);
        return;
      }

      // Verify token is still valid
      const isValid = await authService.verifyToken();
      if (!isValid) {
        setUser(null);
        return;
      }

      // Get user profile
      const response = await authService.getProfile();
      setUser(response.user);
    } catch (err) {
      console.error('Failed to load user:', err);
      setUser(null);
      authService.logout();
    } finally {
      setLoading(false);
    }
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await authService.login({ email, password });
      setUser(response.user);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Login failed';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const register = useCallback(async (name: string, email: string, password: string) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await authService.register({ name, email, password });
      setUser(response.user);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Registration failed';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    authService.logout();
    setUser(null);
    setError(null);
  }, []);

  const saveAssessment = useCallback(async (assessmentData: any) => {
    try {
      setError(null);
      await authService.saveAssessment(assessmentData);
      
      // Update user state to reflect completed assessment
      if (user) {
        setUser({
          ...user,
          assessmentCompleted: true,
          assessmentData
        });
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to save assessment';
      setError(errorMessage);
      throw err;
    }
  }, [user]);

  // Load user on mount
  useEffect(() => {
    loadUser();
  }, [loadUser]);

  return {
    user,
    loading,
    error,
    login,
    register,
    logout,
    saveAssessment,
    clearError
  };
};