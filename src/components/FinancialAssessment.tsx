import React, { useState } from 'react';
import { 
  ArrowRight, 
  ArrowLeft, 
  CheckCircle, 
  User, 
  Target, 
  Clock, 
  DollarSign, 
  TrendingUp, 
  BookOpen,
  Shield,
  Zap,
  AlertTriangle
} from 'lucide-react';

interface AssessmentData {
  // Personal Info
  age: string;
  monthlyIncome: string;
  currentSavings: string;
  
  // Goals
  primaryGoal: string;
  secondaryGoals: string[];
  
  // Timeline
  investmentTimeline: string;
  
  // Investment Capacity
  monthlyInvestment: string;
  
  // Risk Tolerance
  riskTolerance: string;
  
  // Experience
  experienceLevel: string;
}

interface FinancialAssessmentProps {
  onComplete: (data: AssessmentData) => void;
}

export const FinancialAssessment: React.FC<FinancialAssessmentProps> = ({ onComplete }) => {
  const [currentStep, setCurrentStep] = useState(1);
  const [assessmentData, setAssessmentData] = useState<AssessmentData>({
    age: '',
    monthlyIncome: '',
    currentSavings: '',
    primaryGoal: '',
    secondaryGoals: [],
    investmentTimeline: '',
    monthlyInvestment: '',
    riskTolerance: '',
    experienceLevel: ''
  });

  const totalSteps = 6;

  const updateData = (field: keyof AssessmentData, value: any) => {
    setAssessmentData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleNext = () => {
    if (currentStep < totalSteps) {
      setCurrentStep(currentStep + 1);
    } else {
      onComplete(assessmentData);
    }
  };

  const handlePrevious = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }
  };

  const isStepValid = () => {
    switch (currentStep) {
      case 1:
        return assessmentData.age && assessmentData.monthlyIncome && assessmentData.currentSavings;
      case 2:
        return assessmentData.primaryGoal;
      case 3:
        return assessmentData.investmentTimeline;
      case 4:
        return assessmentData.monthlyInvestment;
      case 5:
        return assessmentData.riskTolerance;
      case 6:
        return assessmentData.experienceLevel;
      default:
        return false;
    }
  };

  const renderProgressBar = () => (
    <div className="mb-8">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-gray-600">Step {currentStep} of {totalSteps}</span>
        <span className="text-sm font-medium text-blue-600">{Math.round((currentStep / totalSteps) * 100)}%</span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div 
          className="bg-blue-600 h-2 rounded-full transition-all duration-300 ease-out"
          style={{ width: `${(currentStep / totalSteps) * 100}%` }}
        ></div>
      </div>
    </div>
  );

  const renderStep1 = () => (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
          <User className="w-8 h-8 text-blue-600" />
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Personal Information</h2>
        <p className="text-gray-600">Help us understand your current financial situation</p>
      </div>

      <div>
        <label className="block text-sm font-semibold text-gray-700 mb-3">What's your age?</label>
        <div className="grid grid-cols-2 gap-3">
          {['18-25', '26-35', '36-45', '46-55', '55+'].map((ageRange) => (
            <button
              key={ageRange}
              onClick={() => updateData('age', ageRange)}
              className={`p-4 rounded-lg border-2 text-center font-medium transition-all ${
                assessmentData.age === ageRange
                  ? 'border-blue-500 bg-blue-50 text-blue-700'
                  : 'border-gray-200 hover:border-gray-300 text-gray-700'
              }`}
            >
              {ageRange}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-sm font-semibold text-gray-700 mb-3">Monthly Income (₹)</label>
        <div className="grid grid-cols-1 gap-3">
          {[
            { value: '0-25000', label: 'Under ₹25,000' },
            { value: '25000-50000', label: '₹25,000 - ₹50,000' },
            { value: '50000-100000', label: '₹50,000 - ₹1,00,000' },
            { value: '100000+', label: 'Above ₹1,00,000' }
          ].map((income) => (
            <button
              key={income.value}
              onClick={() => updateData('monthlyIncome', income.value)}
              className={`p-4 rounded-lg border-2 text-left font-medium transition-all ${
                assessmentData.monthlyIncome === income.value
                  ? 'border-blue-500 bg-blue-50 text-blue-700'
                  : 'border-gray-200 hover:border-gray-300 text-gray-700'
              }`}
            >
              {income.label}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-sm font-semibold text-gray-700 mb-3">Current Savings (₹)</label>
        <div className="grid grid-cols-1 gap-3">
          {[
            { value: '0-50000', label: 'Under ₹50,000' },
            { value: '50000-200000', label: '₹50,000 - ₹2,00,000' },
            { value: '200000-500000', label: '₹2,00,000 - ₹5,00,000' },
            { value: '500000+', label: 'Above ₹5,00,000' }
          ].map((savings) => (
            <button
              key={savings.value}
              onClick={() => updateData('currentSavings', savings.value)}
              className={`p-4 rounded-lg border-2 text-left font-medium transition-all ${
                assessmentData.currentSavings === savings.value
                  ? 'border-blue-500 bg-blue-50 text-blue-700'
                  : 'border-gray-200 hover:border-gray-300 text-gray-700'
              }`}
            >
              {savings.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );

  const renderStep2 = () => (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
          <Target className="w-8 h-8 text-green-600" />
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Financial Goals</h2>
        <p className="text-gray-600">What do you want to achieve with your investments?</p>
      </div>

      <div>
        <label className="block text-sm font-semibold text-gray-700 mb-3">Primary Goal</label>
        <div className="space-y-3">
          {[
            { value: 'emergency-fund', label: 'Build Emergency Fund', desc: 'Save 6-12 months of expenses' },
            { value: 'house-down-payment', label: 'House Down Payment', desc: 'Save for your dream home' },
            { value: 'wealth-building', label: 'Long-term Wealth Building', desc: 'Grow wealth over time' },
            { value: 'retirement', label: 'Retirement Planning', desc: 'Secure your future' },
            { value: 'education', label: 'Education Fund', desc: 'Higher studies or children\'s education' }
          ].map((goal) => (
            <button
              key={goal.value}
              onClick={() => updateData('primaryGoal', goal.value)}
              className={`w-full p-4 rounded-lg border-2 text-left transition-all ${
                assessmentData.primaryGoal === goal.value
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="font-semibold text-gray-900">{goal.label}</div>
              <div className="text-sm text-gray-600 mt-1">{goal.desc}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );

  const renderStep3 = () => (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
          <Clock className="w-8 h-8 text-purple-600" />
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Investment Timeline</h2>
        <p className="text-gray-600">When do you need to achieve your primary goal?</p>
      </div>

      <div className="space-y-4">
        {[
          { 
            value: '1-2-years', 
            label: '1-2 Years', 
            desc: 'Short-term goals, lower risk investments',
            icon: <Zap className="w-6 h-6 text-orange-500" />
          },
          { 
            value: '3-7-years', 
            label: '3-7 Years', 
            desc: 'Medium-term goals, balanced approach',
            icon: <TrendingUp className="w-6 h-6 text-blue-500" />
          },
          { 
            value: '10+-years', 
            label: '10+ Years', 
            desc: 'Long-term goals, higher growth potential',
            icon: <Target className="w-6 h-6 text-green-500" />
          }
        ].map((timeline) => (
          <button
            key={timeline.value}
            onClick={() => updateData('investmentTimeline', timeline.value)}
            className={`w-full p-6 rounded-lg border-2 text-left transition-all ${
              assessmentData.investmentTimeline === timeline.value
                ? 'border-blue-500 bg-blue-50'
                : 'border-gray-200 hover:border-gray-300'
            }`}
          >
            <div className="flex items-start gap-4">
              {timeline.icon}
              <div>
                <div className="font-semibold text-gray-900 text-lg">{timeline.label}</div>
                <div className="text-sm text-gray-600 mt-1">{timeline.desc}</div>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );

  const renderStep4 = () => (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <div className="w-16 h-16 bg-yellow-100 rounded-full flex items-center justify-center mx-auto mb-4">
          <DollarSign className="w-8 h-8 text-yellow-600" />
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Monthly Investment</h2>
        <p className="text-gray-600">How much can you invest every month?</p>
      </div>

      <div className="space-y-3">
        {[
          { value: '500-1000', label: '₹500 - ₹1,000', desc: 'Perfect for beginners' },
          { value: '1000-3000', label: '₹1,000 - ₹3,000', desc: 'Good starting amount' },
          { value: '3000-5000', label: '₹3,000 - ₹5,000', desc: 'Solid investment base' },
          { value: '5000-10000', label: '₹5,000 - ₹10,000', desc: 'Strong commitment' },
          { value: '10000+', label: 'Above ₹10,000', desc: 'Excellent investment capacity' }
        ].map((amount) => (
          <button
            key={amount.value}
            onClick={() => updateData('monthlyInvestment', amount.value)}
            className={`w-full p-4 rounded-lg border-2 text-left transition-all ${
              assessmentData.monthlyInvestment === amount.value
                ? 'border-blue-500 bg-blue-50'
                : 'border-gray-200 hover:border-gray-300'
            }`}
          >
            <div className="font-semibold text-gray-900">{amount.label}</div>
            <div className="text-sm text-gray-600 mt-1">{amount.desc}</div>
          </button>
        ))}
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
            <CheckCircle className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-sm text-blue-800">
            <strong>Pro Tip:</strong> Start with what you're comfortable with. You can always increase your investment amount later as your income grows.
          </div>
        </div>
      </div>
    </div>
  );

  const renderStep5 = () => (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
          <TrendingUp className="w-8 h-8 text-red-600" />
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Risk Tolerance</h2>
        <p className="text-gray-600">How comfortable are you with investment fluctuations?</p>
      </div>

      <div className="space-y-4">
        {[
          {
            value: 'conservative',
            label: 'Conservative',
            desc: 'I prefer stable returns and minimal risk',
            detail: 'Suitable for: Fixed deposits, government bonds, low-risk mutual funds',
            icon: <Shield className="w-6 h-6 text-green-500" />,
            color: 'border-green-200 hover:border-green-300'
          },
          {
            value: 'moderate',
            label: 'Moderate',
            desc: 'I can handle some ups and downs for better returns',
            detail: 'Suitable for: Balanced mutual funds, diversified portfolios',
            icon: <TrendingUp className="w-6 h-6 text-blue-500" />,
            color: 'border-blue-200 hover:border-blue-300'
          },
          {
            value: 'aggressive',
            label: 'Aggressive',
            desc: 'I\'m comfortable with high volatility for maximum growth',
            detail: 'Suitable for: Equity funds, individual stocks, growth investments',
            icon: <AlertTriangle className="w-6 h-6 text-red-500" />,
            color: 'border-red-200 hover:border-red-300'
          }
        ].map((risk) => (
          <button
            key={risk.value}
            onClick={() => updateData('riskTolerance', risk.value)}
            className={`w-full p-6 rounded-lg border-2 text-left transition-all ${
              assessmentData.riskTolerance === risk.value
                ? 'border-blue-500 bg-blue-50'
                : risk.color
            }`}
          >
            <div className="flex items-start gap-4">
              {risk.icon}
              <div>
                <div className="font-semibold text-gray-900 text-lg">{risk.label}</div>
                <div className="text-gray-700 mt-1">{risk.desc}</div>
                <div className="text-sm text-gray-600 mt-2">{risk.detail}</div>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );

  const renderStep6 = () => (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <div className="w-16 h-16 bg-indigo-100 rounded-full flex items-center justify-center mx-auto mb-4">
          <BookOpen className="w-8 h-8 text-indigo-600" />
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Investment Experience</h2>
        <p className="text-gray-600">What's your experience with investing?</p>
      </div>

      <div className="space-y-4">
        {[
          {
            value: 'beginner',
            label: 'Beginner',
            desc: 'I\'m new to investing and want to learn',
            detail: 'We\'ll provide educational content and simple investment options'
          },
          {
            value: 'some-experience',
            label: 'Some Experience',
            desc: 'I have basic knowledge and some investment experience',
            detail: 'We\'ll offer intermediate strategies and diversified options'
          },
          {
            value: 'experienced',
            label: 'Experienced',
            desc: 'I\'m comfortable with various investment instruments',
            detail: 'We\'ll provide advanced options and detailed market insights'
          }
        ].map((experience) => (
          <button
            key={experience.value}
            onClick={() => updateData('experienceLevel', experience.value)}
            className={`w-full p-6 rounded-lg border-2 text-left transition-all ${
              assessmentData.experienceLevel === experience.value
                ? 'border-blue-500 bg-blue-50'
                : 'border-gray-200 hover:border-gray-300'
            }`}
          >
            <div className="font-semibold text-gray-900 text-lg">{experience.label}</div>
            <div className="text-gray-700 mt-1">{experience.desc}</div>
            <div className="text-sm text-gray-600 mt-2">{experience.detail}</div>
          </button>
        ))}
      </div>
    </div>
  );

  const renderCurrentStep = () => {
    switch (currentStep) {
      case 1: return renderStep1();
      case 2: return renderStep2();
      case 3: return renderStep3();
      case 4: return renderStep4();
      case 5: return renderStep5();
      case 6: return renderStep6();
      default: return null;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 py-8 px-4">
      <div className="max-w-2xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Financial Assessment</h1>
          <p className="text-gray-600">Help us create a personalized investment plan for you</p>
        </div>

        <div className="bg-white rounded-2xl shadow-xl border border-gray-100 p-8">
          {renderProgressBar()}
          {renderCurrentStep()}

          <div className="flex justify-between mt-8 pt-6 border-t border-gray-200">
            <button
              onClick={handlePrevious}
              disabled={currentStep === 1}
              className="flex items-center gap-2 px-6 py-3 text-gray-600 hover:text-gray-800 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              Previous
            </button>

            <button
              onClick={handleNext}
              disabled={!isStepValid()}
              className="flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all transform hover:scale-[1.02] disabled:transform-none"
            >
              {currentStep === totalSteps ? 'Complete Assessment' : 'Next'}
              <ArrowRight className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};