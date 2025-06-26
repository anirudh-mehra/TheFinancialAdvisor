import React, { useState } from 'react';
import { AuthScreen } from './components/AuthScreen';
import { FinancialAssessment } from './components/FinancialAssessment';
import { Dashboard } from './components/Dashboard';
import { Header } from './components/Header';
import { useAuth } from './hooks/useAuth';

function App() {
  const { user, loading, logout } = useAuth();
  const [isAuthMode, setIsAuthMode] = useState<'login' | 'signup'>('login');

  const toggleAuthMode = () => {
    setIsAuthMode(isAuthMode === 'login' ? 'signup' : 'login');
  };

  // Show loading spinner while checking authentication
  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  // Show auth screen if no user is logged in
  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
        <AuthScreen 
          mode={isAuthMode}
          onToggleMode={toggleAuthMode}
        />
      </div>
    );
  }

  // Show assessment if user hasn't completed it
  if (!user.assessmentCompleted) {
    return <FinancialAssessment />;
  }

  // Show dashboard if user is logged in and assessment is complete
  return (
    <div className="min-h-screen bg-gray-50">
      <Header user={user} onLogout={logout} />
      <Dashboard user={user} />
    </div>
  );
}

export default App;