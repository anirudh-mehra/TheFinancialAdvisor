import React from 'react';
import { WelcomeSection } from './WelcomeSection';
import { InvestmentCategories } from './InvestmentCategories';
import { QuickStats } from './QuickStats';

interface User {
  id: string;
  name: string;
  email: string;
  assessmentCompleted?: boolean;
  assessmentData?: any;
}

interface DashboardProps {
  user: User;
}

export const Dashboard: React.FC<DashboardProps> = ({ user }) => {
  return (
    <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="space-y-8">
        <WelcomeSection user={user} />
        <QuickStats />
        <InvestmentCategories user={user} />
      </div>
    </main>
  );
};