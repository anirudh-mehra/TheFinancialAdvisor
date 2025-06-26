import React from 'react';
import { ArrowRight, TrendingUp, Target } from 'lucide-react';

interface User {
  id: string;
  name: string;
  email: string;
  assessmentCompleted?: boolean;
  assessmentData?: any;
}

interface WelcomeSectionProps {
  user: User;
}

export const WelcomeSection: React.FC<WelcomeSectionProps> = ({ user }) => {
  const assessmentData = user.assessmentData || {};
  
  const getPersonalizedMessage = () => {
    const { riskTolerance, experienceLevel, primaryGoal } = assessmentData;
    
    if (experienceLevel === 'beginner') {
      return "Let's start your investment journey with simple, beginner-friendly options.";
    } else if (riskTolerance === 'conservative') {
      return "We've curated safe investment options that match your conservative approach.";
    } else if (riskTolerance === 'aggressive') {
      return "Ready for high-growth investments? We've got exciting options for you.";
    } else if (primaryGoal === 'emergency-fund') {
      return "Building an emergency fund is smart! Here are the best options for you.";
    } else if (primaryGoal === 'house-down-payment') {
      return "Saving for your dream home? These investments will help you get there.";
    }
    
    return "Ready to take the next step in your investment journey?";
  };

  return (
    <div className="bg-gradient-to-r from-blue-600 to-blue-700 rounded-2xl p-8 text-white">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
        <div className="mb-6 lg:mb-0">
          <h1 className="text-3xl lg:text-4xl font-bold mb-2">
            Welcome back, {user.name}! 👋
          </h1>
          <p className="text-blue-100 text-lg mb-4">
            {getPersonalizedMessage()}
          </p>
          <div className="flex flex-wrap gap-4 text-blue-200 text-sm">
            {assessmentData.riskTolerance && (
              <div className="flex items-center gap-2">
                <Target className="w-4 h-4" />
                Risk Level: {assessmentData.riskTolerance}
              </div>
            )}
            {assessmentData.monthlyInvestment && (
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4" />
                Monthly Budget: ₹{assessmentData.monthlyInvestment.split('-')[0]}+
              </div>
            )}
          </div>
        </div>
        
        <div className="flex flex-col sm:flex-row gap-4">
          <button className="bg-white text-blue-600 px-6 py-3 rounded-lg font-semibold hover:bg-blue-50 transition-colors flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Start Investing
          </button>
          <button className="bg-blue-500 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-400 transition-colors flex items-center gap-2">
            Learn More
            <ArrowRight className="w-5 h-5" />
          </button>
        </div>
      </div>
    </div>
  );
};