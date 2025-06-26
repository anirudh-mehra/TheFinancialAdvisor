import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft, 
  Calculator, 
  TrendingUp, 
  Clock, 
  Shield, 
  Target,
  DollarSign,
  CheckCircle,
  AlertTriangle,
  PieChart,
  BarChart3,
  Lightbulb,
  ArrowRight,
  Star
} from 'lucide-react';

interface User {
  id: string;
  name: string;
  email: string;
  assessmentCompleted?: boolean;
  assessmentData?: any;
}

interface SIPDetailsPageProps {
  user: User;
  onBack: () => void;
}

interface SIPOption {
  name: string;
  category: string;
  returns: string;
  risk: 'Low' | 'Medium' | 'High';
  minSIP: number;
  description: string;
  suitable: string[];
}

export const SIPDetailsPage: React.FC<SIPDetailsPageProps> = ({ user, onBack }) => {
  const [calculatorData, setCalculatorData] = useState({
    monthlyAmount: 5000,
    years: 10,
    expectedReturn: 12
  });

  const assessmentData = user.assessmentData || {};
  const userAge = assessmentData.age ? parseInt(assessmentData.age.split('-')[0]) : 25;
  const userBudget = assessmentData.monthlyInvestment || '5000-10000';
  const userRisk = assessmentData.riskTolerance || 'moderate';
  const userExperience = assessmentData.experienceLevel || 'beginner';

  // Set default calculator amount based on user's budget
  useEffect(() => {
    const budgetRange = userBudget.split('-');
    const minBudget = parseInt(budgetRange[0]) || 5000;
    setCalculatorData(prev => ({
      ...prev,
      monthlyAmount: minBudget
    }));
  }, [userBudget]);

  const sipOptions: SIPOption[] = [
    {
      name: 'HDFC Top 100 Fund',
      category: 'Large Cap',
      returns: '11-13%',
      risk: 'Medium',
      minSIP: 500,
      description: 'Invests in top 100 companies by market cap',
      suitable: ['beginner', 'moderate', 'conservative']
    },
    {
      name: 'SBI Blue Chip Fund',
      category: 'Large Cap',
      returns: '10-12%',
      risk: 'Medium',
      minSIP: 500,
      description: 'Focuses on established blue-chip companies',
      suitable: ['beginner', 'conservative', 'moderate']
    },
    {
      name: 'Axis Midcap Fund',
      category: 'Mid Cap',
      returns: '13-16%',
      risk: 'High',
      minSIP: 1000,
      description: 'Invests in mid-sized companies with growth potential',
      suitable: ['some-experience', 'experienced', 'aggressive']
    },
    {
      name: 'Mirae Asset Large Cap Fund',
      category: 'Large Cap',
      returns: '10-12%',
      risk: 'Medium',
      minSIP: 500,
      description: 'Diversified large-cap equity fund',
      suitable: ['beginner', 'moderate']
    },
    {
      name: 'Parag Parikh Flexi Cap Fund',
      category: 'Flexi Cap',
      returns: '12-15%',
      risk: 'Medium',
      minSIP: 1000,
      description: 'Flexible allocation across market caps',
      suitable: ['some-experience', 'moderate', 'aggressive']
    },
    {
      name: 'ICICI Prudential Balanced Advantage Fund',
      category: 'Hybrid',
      returns: '9-11%',
      risk: 'Low',
      minSIP: 500,
      description: 'Balanced mix of equity and debt',
      suitable: ['beginner', 'conservative']
    }
  ];

  const getPersonalizedSIPs = () => {
    const budgetMin = parseInt(userBudget.split('-')[0]) || 500;
    
    return sipOptions.filter(sip => {
      const matchesRisk = sip.suitable.includes(userRisk);
      const matchesExperience = sip.suitable.includes(userExperience);
      const withinBudget = sip.minSIP <= budgetMin;
      
      return (matchesRisk || matchesExperience) && withinBudget;
    }).sort((a, b) => {
      // Prioritize based on user profile
      const aScore = (a.suitable.includes(userRisk) ? 2 : 0) + 
                    (a.suitable.includes(userExperience) ? 1 : 0);
      const bScore = (b.suitable.includes(userRisk) ? 2 : 0) + 
                    (b.suitable.includes(userExperience) ? 1 : 0);
      return bScore - aScore;
    });
  };

  const calculateSIP = () => {
    const { monthlyAmount, years, expectedReturn } = calculatorData;
    const monthlyRate = expectedReturn / 100 / 12;
    const totalMonths = years * 12;
    
    const futureValue = monthlyAmount * (((Math.pow(1 + monthlyRate, totalMonths) - 1) / monthlyRate) * (1 + monthlyRate));
    const totalInvested = monthlyAmount * totalMonths;
    const totalGains = futureValue - totalInvested;
    
    return {
      futureValue: Math.round(futureValue),
      totalInvested,
      totalGains: Math.round(totalGains)
    };
  };

  const getPersonalizedBenefits = () => {
    const benefits = [];
    
    if (userAge <= 30) {
      benefits.push({
        icon: <Clock className="w-5 h-5 text-blue-600" />,
        title: 'Time is Your Biggest Asset',
        description: `At ${userAge}, you have 30+ years until retirement. Starting SIPs now can help you build a corpus of ₹2-5 crores by retirement.`
      });
    }
    
    if (userRisk === 'conservative') {
      benefits.push({
        icon: <Shield className="w-5 h-5 text-green-600" />,
        title: 'Reduces Risk Through Averaging',
        description: 'SIPs reduce the impact of market volatility through rupee cost averaging, perfect for your conservative approach.'
      });
    }
    
    if (userExperience === 'beginner') {
      benefits.push({
        icon: <Lightbulb className="w-5 h-5 text-yellow-600" />,
        title: 'Perfect for Beginners',
        description: 'No need to time the market or pick individual stocks. Professional fund managers handle the investment decisions.'
      });
    }
    
    const budgetAmount = parseInt(userBudget.split('-')[0]) || 1000;
    benefits.push({
      icon: <DollarSign className="w-5 h-5 text-purple-600" />,
      title: 'Fits Your Budget',
      description: `Starting with just ₹${budgetAmount}/month, you can build substantial wealth over time without straining your finances.`
    });
    
    return benefits;
  };

  const results = calculateSIP();
  const personalizedSIPs = getPersonalizedSIPs();
  const personalizedBenefits = getPersonalizedBenefits();

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-4xl mx-auto px-4 py-4">
          <button
            onClick={onBack}
            className="flex items-center gap-2 text-gray-600 hover:text-gray-900 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
            Back to Dashboard
          </button>
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-4 py-8 space-y-8">
        {/* Hero Section */}
        <div className="bg-gradient-to-r from-blue-600 to-blue-700 rounded-2xl p-8 text-white">
          <div className="flex items-center gap-4 mb-4">
            <div className="w-16 h-16 bg-white/20 rounded-xl flex items-center justify-center">
              <PieChart className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">Systematic Investment Plans (SIPs)</h1>
              <p className="text-blue-100">Your gateway to disciplined wealth creation</p>
            </div>
          </div>
          <p className="text-lg text-blue-100">
            Perfect for {userExperience === 'beginner' ? 'beginners like you' : 'your investment style'} - 
            start with as little as ₹500/month and build wealth systematically.
          </p>
        </div>

        {/* What is SIP */}
        <div className="bg-white rounded-xl p-8 shadow-sm border">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center gap-3">
            <Lightbulb className="w-7 h-7 text-yellow-500" />
            What is SIP?
          </h2>
          <div className="prose prose-lg max-w-none">
            <p className="text-gray-700 leading-relaxed mb-4">
              A Systematic Investment Plan (SIP) is like a recurring deposit for mutual funds. Instead of investing 
              a large amount at once, you invest a fixed amount every month. Think of it as paying an EMI to your future self!
            </p>
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
              <h3 className="font-semibold text-blue-900 mb-2">Simple Example:</h3>
              <p className="text-blue-800">
                Instead of investing ₹60,000 at once, you invest ₹5,000 every month for 12 months. 
                This way, you buy more units when prices are low and fewer when prices are high, 
                averaging out your cost over time.
              </p>
            </div>
          </div>
        </div>

        {/* How it Works */}
        <div className="bg-white rounded-xl p-8 shadow-sm border">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center gap-3">
            <BarChart3 className="w-7 h-7 text-green-500" />
            How SIP Works
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                step: '1',
                title: 'Choose Amount & Fund',
                description: 'Decide how much to invest monthly and select a mutual fund',
                icon: <Target className="w-6 h-6 text-blue-600" />
              },
              {
                step: '2',
                title: 'Auto-Debit Setup',
                description: 'Money is automatically debited from your bank account every month',
                icon: <Clock className="w-6 h-6 text-green-600" />
              },
              {
                step: '3',
                title: 'Units Allocated',
                description: 'You get mutual fund units based on current NAV (Net Asset Value)',
                icon: <PieChart className="w-6 h-6 text-purple-600" />
              }
            ].map((step, index) => (
              <div key={index} className="text-center">
                <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white font-bold text-sm">
                    {step.step}
                  </div>
                </div>
                <div className="mb-3">{step.icon}</div>
                <h3 className="font-semibold text-gray-900 mb-2">{step.title}</h3>
                <p className="text-gray-600 text-sm">{step.description}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Personalized Benefits */}
        <div className="bg-white rounded-xl p-8 shadow-sm border">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center gap-3">
            <Star className="w-7 h-7 text-yellow-500" />
            Why SIP is Perfect for You
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {personalizedBenefits.map((benefit, index) => (
              <div key={index} className="flex gap-4 p-4 bg-gray-50 rounded-lg">
                <div className="flex-shrink-0">
                  {benefit.icon}
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900 mb-1">{benefit.title}</h3>
                  <p className="text-gray-600 text-sm">{benefit.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* SIP Calculator */}
        <div className="bg-white rounded-xl p-8 shadow-sm border">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center gap-3">
            <Calculator className="w-7 h-7 text-blue-500" />
            SIP Calculator
          </h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">
                  Monthly Investment Amount (₹)
                </label>
                <input
                  type="number"
                  value={calculatorData.monthlyAmount}
                  onChange={(e) => setCalculatorData(prev => ({
                    ...prev,
                    monthlyAmount: parseInt(e.target.value) || 0
                  }))}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  min="500"
                  step="500"
                />
              </div>
              
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">
                  Investment Period (Years)
                </label>
                <input
                  type="number"
                  value={calculatorData.years}
                  onChange={(e) => setCalculatorData(prev => ({
                    ...prev,
                    years: parseInt(e.target.value) || 0
                  }))}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  min="1"
                  max="40"
                />
              </div>
              
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">
                  Expected Annual Return (%)
                </label>
                <input
                  type="number"
                  value={calculatorData.expectedReturn}
                  onChange={(e) => setCalculatorData(prev => ({
                    ...prev,
                    expectedReturn: parseFloat(e.target.value) || 0
                  }))}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  min="1"
                  max="20"
                  step="0.5"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Historical average for equity mutual funds: 10-12%
                </p>
              </div>
            </div>
            
            <div className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-xl p-6">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Your Investment Summary</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center py-2 border-b border-blue-200">
                  <span className="text-gray-700">Monthly Investment</span>
                  <span className="font-semibold text-gray-900">₹{calculatorData.monthlyAmount.toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-blue-200">
                  <span className="text-gray-700">Total Invested</span>
                  <span className="font-semibold text-gray-900">₹{results.totalInvested.toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-blue-200">
                  <span className="text-gray-700">Total Gains</span>
                  <span className="font-semibold text-green-600">₹{results.totalGains.toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-center py-3 bg-blue-100 rounded-lg px-4">
                  <span className="text-blue-900 font-semibold">Final Amount</span>
                  <span className="font-bold text-blue-900 text-xl">₹{results.futureValue.toLocaleString()}</span>
                </div>
              </div>
              
              <div className="mt-6 p-4 bg-white rounded-lg border border-blue-200">
                <div className="flex items-center gap-2 mb-2">
                  <TrendingUp className="w-5 h-5 text-green-600" />
                  <span className="font-semibold text-gray-900">Wealth Multiplier</span>
                </div>
                <p className="text-sm text-gray-600">
                  Your money will grow by <span className="font-bold text-green-600">
                    {(results.futureValue / results.totalInvested).toFixed(1)}x
                  </span> in {calculatorData.years} years!
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Recommended SIP Options */}
        <div className="bg-white rounded-xl p-8 shadow-sm border">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center gap-3">
            <Target className="w-7 h-7 text-green-500" />
            Recommended SIP Options for You
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {personalizedSIPs.slice(0, 4).map((sip, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="font-bold text-gray-900 mb-1">{sip.name}</h3>
                    <span className="text-sm text-blue-600 bg-blue-100 px-2 py-1 rounded-full">
                      {sip.category}
                    </span>
                  </div>
                  <div className="text-right">
                    <div className="text-lg font-bold text-green-600">{sip.returns}</div>
                    <div className="text-xs text-gray-500">Expected Returns</div>
                  </div>
                </div>
                
                <p className="text-gray-600 text-sm mb-4">{sip.description}</p>
                
                <div className="flex justify-between items-center mb-4">
                  <div>
                    <span className="text-xs text-gray-500">Min SIP</span>
                    <div className="font-semibold">₹{sip.minSIP}</div>
                  </div>
                  <div className={`px-2 py-1 rounded-full text-xs font-medium ${
                    sip.risk === 'Low' ? 'bg-green-100 text-green-800' :
                    sip.risk === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-red-100 text-red-800'
                  }`}>
                    {sip.risk} Risk
                  </div>
                </div>
                
                <button className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg font-semibold hover:bg-blue-700 transition-colors">
                  Start SIP
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* How to Get Started */}
        <div className="bg-white rounded-xl p-8 shadow-sm border">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center gap-3">
            <ArrowRight className="w-7 h-7 text-purple-500" />
            How to Get Started
          </h2>
          <div className="space-y-4">
            {[
              'Complete your KYC (Know Your Customer) verification online',
              'Choose a mutual fund based on your risk profile and goals',
              'Set up auto-debit mandate with your bank',
              'Start your SIP with as little as ₹500/month',
              'Monitor your investments quarterly (not daily!)',
              'Increase SIP amount annually as your income grows'
            ].map((step, index) => (
              <div key={index} className="flex items-start gap-3">
                <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-blue-600 font-bold text-sm">{index + 1}</span>
                </div>
                <p className="text-gray-700">{step}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Risk Factors */}
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-8">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center gap-3">
            <AlertTriangle className="w-7 h-7 text-yellow-600" />
            Important Things to Know
          </h2>
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-yellow-600 mt-0.5 flex-shrink-0" />
              <div>
                <h3 className="font-semibold text-gray-900 mb-1">Market Risk</h3>
                <p className="text-gray-700 text-sm">
                  Mutual fund investments are subject to market risks. Your returns may vary based on market conditions.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Clock className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div>
                <h3 className="font-semibold text-gray-900 mb-1">Stay Invested</h3>
                <p className="text-gray-700 text-sm">
                  SIPs work best when you stay invested for the long term (5+ years). Avoid stopping during market downturns.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
              <div>
                <h3 className="font-semibold text-gray-900 mb-1">Diversification</h3>
                <p className="text-gray-700 text-sm">
                  Don't put all your money in one fund. Diversify across different categories for better risk management.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* CTA Section */}
        <div className="bg-gradient-to-r from-green-600 to-green-700 rounded-xl p-8 text-white text-center">
          <h2 className="text-2xl font-bold mb-4">Ready to Start Your SIP Journey?</h2>
          <p className="text-green-100 mb-6">
            Join millions of Indians who are building wealth through SIPs. 
            Start with just ₹{parseInt(userBudget.split('-')[0]) || 500}/month today!
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button className="bg-white text-green-600 px-8 py-3 rounded-lg font-semibold hover:bg-green-50 transition-colors">
              Start Your First SIP
            </button>
            <button className="bg-green-500 text-white px-8 py-3 rounded-lg font-semibold hover:bg-green-400 transition-colors">
              Talk to Expert
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};