import React, { useState } from 'react';
import { AuthScreen } from './components/AuthScreen';
import { FinancialAssessment } from './components/FinancialAssessment';
import { Dashboard } from './components/Dashboard';
import { Header } from './components/Header';

interface User {
  id: string;
  name: string;
  email: string;
  assessmentCompleted?: boolean;
  assessmentData?: any;
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthMode, setIsAuthMode] = useState<'login' | 'signup'>('login');

  const handleLogin = (userData: { name: string; email: string }) => {
    setUser({
      id: Date.now().toString(),
      ...userData,
      assessmentCompleted: false
    });
  };

  const handleAssessmentComplete = (assessmentData: any) => {
    if (user) {
      setUser({
        ...user,
        assessmentCompleted: true,
        assessmentData
      });
    }
  };

  const handleLogout = () => {
    setUser(null);
  };

  const toggleAuthMode = () => {
    setIsAuthMode(isAuthMode === 'login' ? 'signup' : 'login');
  };

  // Show auth screen if no user
  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
        <AuthScreen 
          mode={isAuthMode}
          onLogin={handleLogin}
          onToggleMode={toggleAuthMode}
        />
      </div>
    );
  }

  // Show assessment if user hasn't completed it
  if (!user.assessmentCompleted) {
    return <FinancialAssessment onComplete={handleAssessmentComplete} />;
  }

  // Show dashboard if user is logged in and assessment is complete
  return (
    <div className="min-h-screen bg-gray-50">
      <Header user={user} onLogout={handleLogout} />
      <Dashboard user={user} />
    </div>
  );
}

export default App;