import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ChevronRight, ChevronLeft, Shield } from 'lucide-react';

const steps = ['Personal Information', 'Verification'];

export default function Registration() {
  const [currentStep, setCurrentStep] = useState(0);
  const [formData, setFormData] = useState({
    full_name: '',
    email: '',
    phone: '',
    bvn: '',
    nin: '',
    date_of_birth: '',
    address: '',
    occupation: '',
  });
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const nextStep = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      // Submit form data to server here
      navigate('/pin-setup');
    }
  };

  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  return (
    <div className="flex min-h-screen bg-gray-50">
      <div className="flex-1 flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div className="mx-auto w-full max-w-md">
          <div className="text-center">
            <h2 className="text-3xl font-extrabold text-gray-900">
              Secure Cipher Bank
            </h2>
            <p className="mt-2 text-sm text-gray-600">
              Create your secure digital banking account
            </p>
          </div>

          <div className="mt-8">
            {/* Step indicator */}
            <div className="mb-8">
              <div className="flex items-center justify-between">
                {steps.map((step, index) => (
                  <div key={step} className="flex items-center">
                    <div className={`flex items-center justify-center h-8 w-8 rounded-full ${
                      currentStep >= index ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-600'
                    }`}>
                      {index + 1}
                    </div>
                    <div className="ml-2 text-sm font-medium text-gray-700">{step}</div>
                    {index < steps.length - 1 && (
                      <div className="ml-2 h-0.5 w-16 bg-gray-200"></div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
              {currentStep === 0 ? (
                <form>
                  <div className="space-y-6">
                    <div>
                      <label htmlFor="full_name" className="block text-sm font-medium text-gray-700">
                        Full Name
                      </label>
                      <div className="mt-1">
                        <input
                          id="full_name"
                          name="full_name"
                          type="text"
                          required
                          value={formData.full_name}
                          onChange={handleChange}
                          className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                        />
                      </div>
                    </div>

                    <div>
                      <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                        Email Address
                      </label>
                      <div className="mt-1">
                        <input
                          id="email"
                          name="email"
                          type="email"
                          required
                          value={formData.email}
                          onChange={handleChange}
                          className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                        />
                      </div>
                    </div>

                    <div>
                      <label htmlFor="phone" className="block text-sm font-medium text-gray-700">
                        Phone Number
                      </label>
                      <div className="mt-1">
                        <input
                          id="phone"
                          name="phone"
                          type="tel"
                          required
                          value={formData.phone}
                          onChange={handleChange}
                          className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                        />
                      </div>
                    </div>
                  </div>
                </form>
              ) : (
                <form>
                  <div className="space-y-6">
                    <div>
                      <label htmlFor="bvn" className="block text-sm font-medium text-gray-700">
                        Bank Verification Number (BVN)
                      </label>
                      <div className="mt-1">
                        <input
                          id="bvn"
                          name="bvn"
                          type="text"
                          required
                          value={formData.bvn}
                          onChange={handleChange}
                          className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                        />
                      </div>
                    </div>

                    <div>
                      <label htmlFor="nin" className="block text-sm font-medium text-gray-700">
                        National Identification Number (NIN)
                      </label>
                      <div className="mt-1">
                        <input
                          id="nin"
                          name="nin"
                          type="text"
                          required
                          value={formData.nin}
                          onChange={handleChange}
                          className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                        />
                      </div>
                    </div>

                    <div>
                      <label htmlFor="date_of_birth" className="block text-sm font-medium text-gray-700">
                        Date of Birth
                      </label>
                      <div className="mt-1">
                        <input
                          id="date_of_birth"
                          name="date_of_birth"
                          type="date"
                          required
                          value={formData.date_of_birth}
                          onChange={handleChange}
                          className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                        />
                      </div>
                    </div>

                    <div>
                      <label htmlFor="address" className="block text-sm font-medium text-gray-700">
                        Address
                      </label>
                      <div className="mt-1">
                        <input
                          id="address"
                          name="address"
                          type="text"
                          required
                          value={formData.address}
                          onChange={handleChange}
                          className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                        />
                      </div>
                    </div>

                    <div>
                      <label htmlFor="occupation" className="block text-sm font-medium text-gray-700">
                        Occupation
                      </label>
                      <div className="mt-1">
                        <input
                          id="occupation"
                          name="occupation"
                          type="text"
                          required
                          value={formData.occupation}
                          onChange={handleChange}
                          className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                        />
                      </div>
                    </div>
                  </div>
                </form>
              )}

              <div className="mt-6 flex justify-between">
                <button
                  type="button"
                  onClick={prevStep}
                  disabled={currentStep === 0}
                  className={`inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 ${
                    currentStep === 0 ? 'opacity-50 cursor-not-allowed' : ''
                  }`}
                >
                  <ChevronLeft className="-ml-1 mr-2 h-5 w-5" />
                  Back
                </button>
                <button
                  type="button"
                  onClick={nextStep}
                  className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                >
                  {currentStep < steps.length - 1 ? 'Next' : 'Create Account'}
                  <ChevronRight className="ml-2 -mr-1 h-5 w-5" />
                </button>
              </div>
              
              <div className="mt-6 bg-green-50 rounded-md p-4 flex items-center">
                <Shield className="h-5 w-5 text-green-500 mr-2" />
                <p className="text-sm text-green-700">
                  <span className="font-semibold">Bank-level Security:</span> Your data is encrypted and protected with military-grade security.
                </p>
              </div>
              
              <div className="mt-6 text-center">
                <p className="text-sm text-gray-600">
                  Already have an account with Secure Cipher Bank?
                </p>
                <Link
                  to="/login"
                  className="mt-2 inline-block font-medium text-green-600 hover:text-green-500"
                >
                  Sign In to Your Account
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
