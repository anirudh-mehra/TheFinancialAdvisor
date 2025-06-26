import React, { useState } from 'react';
import { 
  PieChart, 
  TrendingUp, 
  Shield, 
  Building, 
  Coins, 
  CreditCard,
  ArrowRight,
  Star,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import { SIPDetailsPage } from './SIPDetailsPage';

interface User {
  id: string;
  name: string;
  email: string;
  assessmentCompleted?: boolean;
  assessmentData?: any;
}

interface InvestmentCategoriesProps {
  user: User;
}

interface InvestmentOption {
  id: string;
  icon: React.ComponentType<any>;
  title: string;
  description: string;
  whyRecommended: string;
  expectedReturns: string;
  risk: 'Low' | 'Medium' | 'High' | 'Very High';
  minAmount: string;
  features: string[];
  recommended: boolean;
  priority: number;
  color: string;
  bgColor: string;
  borderColor: string;
  suitableFor: string[];
}

export const InvestmentCategories: React.FC<InvestmentCategoriesProps> = ({ user }) => {
  const [selectedInvestment, setSelectedInvestment] = useState<string | null>(null);
  const assessmentData = user.assessmentData || {};

  const allInvestmentOptions: InvestmentOption[] = [
    {
      id: 'sip',
      icon: PieChart,
      title: 'Systematic Investment Plans (SIPs)',
      description: 'Start small, dream big with monthly investments as low as ₹500',
      whyRecommended: 'Perfect for beginners with disciplined investing approach',
      expectedReturns: '10-15% annually',
      risk: 'Medium',
      minAmount: '₹500',
      features: ['Auto-debit facility', 'Power of compounding', 'Rupee cost averaging'],
      recommended: true,
      priority: 1,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      borderColor: 'border-blue-200',
      suitableFor: ['beginner', 'some-experience', 'conservative', 'moderate', '500-1000', '1000-3000']
    },
    {
      id: 'etf',
      icon: Shield,
      title: 'Exchange Traded Funds (ETFs)',
      description: 'Diversify instantly with funds that track market indices',
      whyRecommended: 'Low-cost diversification with professional management',
      expectedReturns: '8-12% annually',
      risk: 'Medium',
      minAmount: '₹100',
      features: ['Low expense ratio', 'Market tracking', 'High liquidity'],
      recommended: true,
      priority: 2,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50',
      borderColor: 'border-purple-200',
      suitableFor: ['beginner', 'some-experience', 'experienced', 'conservative', 'moderate']
    },
    {
      id: 'bonds',
      icon: CreditCard,
      title: 'Government Bonds',
      description: 'Safe and steady returns backed by government guarantee',
      whyRecommended: 'Ideal for conservative investors seeking stable returns',
      expectedReturns: '6-8% annually',
      risk: 'Low',
      minAmount: '₹1,000',
      features: ['Government backing', 'Fixed returns', 'Tax benefits'],
      recommended: false,
      priority: 3,
      color: 'text-indigo-600',
      bgColor: 'bg-indigo-50',
      borderColor: 'border-indigo-200',
      suitableFor: ['conservative', '1-2-years', 'emergency-fund']
    },
    {
      id: 'equity',
      icon: TrendingUp,
      title: 'Direct Equity',
      description: 'Buy shares directly and own a piece of your favorite companies',
      whyRecommended: 'Higher growth potential for experienced investors',
      expectedReturns: '12-18% annually',
      risk: 'High',
      minAmount: '₹1',
      features: ['Direct ownership', 'Voting rights', 'Dividend income'],
      recommended: false,
      priority: 4,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
      borderColor: 'border-green-200',
      suitableFor: ['experienced', 'aggressive', '10+-years', 'wealth-building']
    },
    {
      id: 'reit',
      icon: Building,
      title: 'Real Estate Investment Trusts (REITs)',
      description: 'Invest in real estate without buying property',
      whyRecommended: 'Diversify into real estate with smaller capital',
      expectedReturns: '8-12% annually',
      risk: 'Medium',
      minAmount: '₹2,000',
      features: ['Real estate exposure', 'Regular dividends', 'Professional management'],
      recommended: false,
      priority: 5,
      color: 'text-teal-600',
      bgColor: 'bg-teal-50',
      borderColor: 'border-teal-200',
      suitableFor: ['some-experience', 'experienced', 'moderate', 'house-down-payment']
    },
    {
      id: 'crypto',
      icon: Coins,
      title: 'Cryptocurrency',
      description: 'Explore digital assets with proper risk management',
      whyRecommended: 'For tech-savvy investors comfortable with volatility',
      expectedReturns: '15-25% annually (highly volatile)',
      risk: 'Very High',
      minAmount: '₹100',
      features: ['24/7 trading', 'Global access', 'High volatility'],
      recommended: false,
      priority: 6,
      color: 'text-orange-600',
      bgColor: 'bg-orange-50',
      borderColor: 'border-orange-200',
      suitableFor: ['experienced', 'aggressive', '10+-years', '26-35', '36-45']
    }
  ];

  const getPersonalizedRecommendations = (): InvestmentOption[] => {
    const {
      age,
      monthlyIncome,
      currentSavings,
      primaryGoal,
      investmentTimeline,
      monthlyInvestment,
      riskTolerance,
      experienceLevel
    } = assessmentData;

    return allInvestmentOptions.map(option => {
      let score = 0;
      let personalizedReason = option.whyRecommended;

      // Score based on experience level
      if (option.suitableFor.includes(experienceLevel)) score += 3;

      // Score based on risk tolerance
      if (option.suitableFor.includes(riskTolerance)) score += 3;

      // Score based on timeline
      if (option.suitableFor.includes(investmentTimeline)) score += 2;

      // Score based on primary goal
      if (option.suitableFor.includes(primaryGoal)) score += 2;

      // Score based on age group
      if (option.suitableFor.includes(age)) score += 1;

      // Score based on monthly investment capacity
      if (option.suitableFor.includes(monthlyInvestment)) score += 1;

      // Customize recommendation reason based on user profile
      if (experienceLevel === 'beginner' && option.id === 'sip') {
        personalizedReason = 'Perfect starting point for new investors like you';
      } else if (riskTolerance === 'conservative' && option.id === 'bonds') {
        personalizedReason = 'Matches your conservative risk preference perfectly';
      } else if (riskTolerance === 'aggressive' && option.id === 'equity') {
        personalizedReason = 'Aligns with your high risk tolerance for maximum growth';
      } else if (primaryGoal === 'house-down-payment' && option.id === 'reit') {
        personalizedReason = 'Great way to invest in real estate for your home goal';
      } else if (experienceLevel === 'experienced' && option.id === 'crypto') {
        personalizedReason = 'Your experience makes you suitable for this volatile asset';
      }

      return {
        ...option,
        whyRecommended: personalizedReason,
        recommended: score >= 4,
        priority: score
      };
    }).sort((a, b) => b.priority - a.priority);
  };

  const personalizedOptions = getPersonalizedRecommendations();
  const recommendedOptions = personalizedOptions.filter(option => option.recommended);
  const otherOptions = personalizedOptions.filter(option => !option.recommended);

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'Low': return 'text-green-600 bg-green-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'High': return 'text-orange-600 bg-orange-100';
      case 'Very High': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const handleLearnMore = (investmentId: string) => {
    setSelectedInvestment(investmentId);
  };

  const handleBack = () => {
    setSelectedInvestment(null);
  };

  // Show detailed page if an investment is selected
  if (selectedInvestment === 'sip') {
    return <SIPDetailsPage user={user} onBack={handleBack} />;
  }

  const renderInvestmentCard = (option: InvestmentOption, isRecommended: boolean = false) => {
    const Icon = option.icon;
    return (
      <div
        key={option.id}
        className={`bg-white rounded-xl p-6 border-2 ${option.borderColor} hover:shadow-lg transition-all duration-200 relative overflow-hidden group ${
          isRecommended ? 'ring-2 ring-blue-200' : ''
        }`}
      >
        {isRecommended && (
          <div className="absolute top-4 right-4">
            <div className="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-xs font-semibold flex items-center gap-1">
              <Star className="w-3 h-3" />
              Recommended for You
            </div>
          </div>
        )}

        <div className={`w-14 h-14 ${option.bgColor} rounded-xl flex items-center justify-center mb-4`}>
          <Icon className={`w-7 h-7 ${option.color}`} />
        </div>

        <h3 className="text-xl font-bold text-gray-900 mb-2">{option.title}</h3>
        <p className="text-gray-600 mb-3 text-sm leading-relaxed">{option.description}</p>

        {isRecommended && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 mb-4">
            <div className="flex items-start gap-2">
              <CheckCircle className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
              <p className="text-sm text-blue-800 font-medium">{option.whyRecommended}</p>
            </div>
          </div>
        )}

        <div className="space-y-3 mb-4">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-700">Expected Returns</span>
            <span className="text-sm font-bold text-green-600">{option.expectedReturns}</span>
          </div>
          
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-700">Risk Level</span>
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskColor(option.risk)}`}>
              {option.risk}
            </span>
          </div>
          
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-700">Minimum Amount</span>
            <span className="text-sm font-bold text-gray-900">{option.minAmount}</span>
          </div>
        </div>

        <div className="space-y-2 mb-6">
          {option.features.map((feature, featureIndex) => (
            <div key={featureIndex} className="flex items-center gap-2 text-sm text-gray-600">
              <div className="w-1.5 h-1.5 bg-blue-500 rounded-full"></div>
              {feature}
            </div>
          ))}
        </div>

        <button 
          onClick={() => handleLearnMore(option.id)}
          className={`w-full py-3 px-4 rounded-lg font-semibold transition-colors flex items-center justify-center gap-2 ${
            isRecommended 
              ? 'bg-blue-600 text-white hover:bg-blue-700' 
              : 'bg-gray-900 text-white hover:bg-gray-800 group-hover:bg-blue-600'
          }`}
        >
          Learn More
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    );
  };

  return (
    <div>
      {recommendedOptions.length > 0 && (
        <div className="mb-12">
          <div className="mb-8">
            <h2 className="text-3xl font-bold text-gray-900 mb-2">Recommended for You</h2>
            <p className="text-gray-600 text-lg">
              Based on your financial assessment, these investment options are tailored for your profile
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-8">
            {recommendedOptions.map(option => renderInvestmentCard(option, true))}
          </div>

          <div className="bg-gradient-to-r from-green-50 to-blue-50 rounded-xl p-6 border border-green-200">
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center flex-shrink-0">
                <CheckCircle className="w-5 h-5 text-green-600" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Why These Recommendations?</h3>
                <p className="text-gray-700 text-sm leading-relaxed">
                  Our recommendations are based on your risk tolerance ({assessmentData.riskTolerance}), 
                  experience level ({assessmentData.experienceLevel}), investment timeline ({assessmentData.investmentTimeline}), 
                  and primary goal ({assessmentData.primaryGoal?.replace('-', ' ')}). 
                  Start with the recommended options and gradually explore others as you gain experience.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {otherOptions.length > 0 && (
        <div>
          <div className="mb-8">
            <h2 className="text-3xl font-bold text-gray-900 mb-2">Other Investment Options</h2>
            <p className="text-gray-600 text-lg">
              Explore additional investment categories as you grow your portfolio
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            {otherOptions.map(option => renderInvestmentCard(option, false))}
          </div>
        </div>
      )}

      <div className="mt-12 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl p-6 border border-blue-200">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between">
          <div className="mb-4 md:mb-0">
            <h3 className="text-xl font-bold text-gray-900 mb-2">Want to Update Your Preferences?</h3>
            <p className="text-gray-600">
              Retake the financial assessment to get updated recommendations based on your current situation
            </p>
          </div>
          <button className="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors flex items-center gap-2">
            Retake Assessment
            <ArrowRight className="w-5 h-5" />
          </button>
        </div>
      </div>
    </div>
  );
};