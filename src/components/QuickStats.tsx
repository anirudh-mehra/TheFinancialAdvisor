import React from 'react';
import { TrendingUp, DollarSign, Target, Calendar } from 'lucide-react';

interface User {
  id: string;
  name: string;
  email: string;
  assessmentCompleted?: boolean;
  assessmentData?: any;
}

interface QuickStatsProps {
  user?: User;
}

export const QuickStats: React.FC<QuickStatsProps> = ({ user }) => {
  const assessmentData = user?.assessmentData || {};
  
  const getGoalText = (goal: string) => {
    switch (goal) {
      case 'emergency-fund': return 'Emergency Fund';
      case 'house-down-payment': return 'House Down Payment';
      case 'wealth-building': return 'Wealth Building';
      case 'retirement': return 'Retirement Planning';
      case 'education': return 'Education Fund';
      default: return 'Set your goal';
    }
  };

  const stats = [
    {
      icon: DollarSign,
      label: 'Portfolio Value',
      value: '₹0',
      subtext: 'Start your first investment',
      color: 'text-green-600',
      bgColor: 'bg-green-50'
    },
    {
      icon: TrendingUp,
      label: 'Monthly SIP',
      value: assessmentData.monthlyInvestment ? 
        `₹${assessmentData.monthlyInvestment.split('-')[0]}+` : '₹0',
      subtext: assessmentData.monthlyInvestment ? 
        'Based on your capacity' : 'Set up recurring investments',
      color: 'text-blue-600',
      bgColor: 'bg-blue-50'
    },
    {
      icon: Target,
      label: 'Primary Goal',
      value: assessmentData.primaryGoal ? '1' : '0',
      subtext: assessmentData.primaryGoal ? 
        getGoalText(assessmentData.primaryGoal) : 'Define financial targets',
      color: 'text-purple-600',
      bgColor: 'bg-purple-50'
    },
    {
      icon: Calendar,
      label: 'Investment Timeline',
      value: assessmentData.investmentTimeline ? 
        assessmentData.investmentTimeline.replace('-', ' ') : '0 days',
      subtext: assessmentData.investmentTimeline ? 
        'Your investment horizon' : 'Time in market',
      color: 'text-orange-600',
      bgColor: 'bg-orange-50'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
      {stats.map((stat, index) => {
        const Icon = stat.icon;
        return (
          <div key={index} className="bg-white rounded-xl p-6 shadow-sm border border-gray-200 hover:shadow-md transition-shadow">
            <div className="flex items-center gap-4">
              <div className={`w-12 h-12 ${stat.bgColor} rounded-lg flex items-center justify-center`}>
                <Icon className={`w-6 h-6 ${stat.color}`} />
              </div>
              <div className="flex-1">
                <p className="text-sm text-gray-600 mb-1">{stat.label}</p>
                <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
                <p className="text-xs text-gray-500">{stat.subtext}</p>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};