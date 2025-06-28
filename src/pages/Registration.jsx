import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ChevronRight, ChevronLeft, Shield, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const steps = ['Personal Information', 'Account Setup', 'Verification'];

export default function Registration() {
  const [currentStep, setCurrentStep] = useState(0);
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    email: '',
    username: '',
    password: '',
    confirm_password: '',
    phone: '',
    bvn: '',
    nin: '',
    date_of_birth: '',
    address: '',
    occupation: '',
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  const { register } = useAuth();
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear error when field is updated
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const validateStep = () => {
    let stepErrors = {};
    let isValid = true;
    
    if (currentStep === 0) {
      // Validate personal information
      if (!formData.first_name.trim()) {
        stepErrors.first_name = 'First name is required';
        isValid = false;
      }
      
      if (!formData.last_name.trim()) {
        stepErrors.last_name = 'Last name is required';
        isValid = false;
      }
      
      if (!formData.email.trim()) {
        stepErrors.email = 'Email is required';
        isValid = false;
      } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
        stepErrors.email = 'Email is invalid';
        isValid = false;
      }
      
      if (!formData.phone.trim()) {
        stepErrors.phone = 'Phone number is required';
        isValid = false;
      }
    } else if (currentStep === 1) {
      // Validate account setup
      if (!formData.username.trim()) {
        stepErrors.username = 'Username is required';
        isValid = false;
      }
      
      if (!formData.password) {
        stepErrors.password = 'Password is required';
        isValid = false;
      } else if (formData.password.length < 8) {
        stepErrors.password = 'Password must be at least 8 characters';
        isValid = false;
      }
      
      if (formData.password !== formData.confirm_password) {
        stepErrors.confirm_password = 'Passwords do not match';
        isValid = false;
      }
    } else if (currentStep === 2) {
      // Validate verification info
      if (!formData.bvn.trim()) {
        stepErrors.bvn = 'BVN is required';
        isValid = false;
      } else if (!/^\d{11}$/.test(formData.bvn)) {
        stepErrors.bvn = 'BVN must be 11 digits';
        isValid = false;
      }
      
      if (!formData.nin.trim()) {
        stepErrors.nin = 'NIN is required';
        isValid = false;
      } else if (!/^\d{11}$/.test(formData.nin)) {
        stepErrors.nin = 'NIN must be 11 digits';
        isValid = false;
      }
      
      if (!formData.date_of_birth) {
        stepErrors.date_of_birth = 'Date of birth is required';
        isValid = false;
      }
      
      if (!formData.address.trim()) {
        stepErrors.address = 'Address is required';
        isValid = false;
      }
      
      if (!formData.occupation.trim()) {
        stepErrors.occupation = 'Occupation is required';
        isValid = false;
      }
    }
    
    setErrors(stepErrors);
    return isValid;
  };

  const nextStep = () => {
    if (validateStep()) {
      if (currentStep < steps.length - 1) {
        setCurrentStep(currentStep + 1);
      } else {
        handleSubmit();
      }
    }
  };

  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };
  
  const handleSubmit = async () => {
    setIsSubmitting(true);
    
    try {
      // Prepare data for submission
      const userData = {
        username: formData.username,
        password: formData.password,
        email: formData.email,
        first_name: formData.first_name,
        last_name: formData.last_name,
        phone: formData.phone,
        bvn: formData.bvn,
        nin: formData.nin,
        date_of_birth: formData.date_of_birth,
        address: formData.address,
        occupation: formData.occupation,
      };
      
      // Register user with API
      await register(userData);
      
      // Navigate to PIN setup page
      navigate('/pin-setup');
    } catch (error) {
      console.error('Registration error:', error);
      
      // Handle API errors
      if (error.data) {
        setErrors(prev => ({ ...prev, ...error.data }));
      } else {
        setErrors({ general: 'An error occurred during registration. Please try again.' });
      }
    } finally {
      setIsSubmitting(false);
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
              {/* General error message */}
              {errors.general && (
                <div className="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded relative">
                  <div className="flex">
                    <AlertCircle className="h-5 w-5 mr-2" />
                    <span>{errors.general}</span>
                  </div>
                </div>
              )}

              {currentStep === 0 ? (
                <form>
                  <div className="space-y-6">
                    <div>
                      <label htmlFor="first_name" className="block text-sm font-medium text-gray-700">
                        First Name
                      </label>
                      <div className="mt-1">
                        <input
                          id="first_name"
                          name="first_name"
                          type="text"
                          required
                          value={formData.first_name}
                          onChange={handleChange}
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.first_name ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.first_name && (
                          <p className="mt-1 text-sm text-red-600">{errors.first_name}</p>
                        )}
                      </div>
                    </div>

                    <div>
                      <label htmlFor="last_name" className="block text-sm font-medium text-gray-700">
                        Last Name
                      </label>
                      <div className="mt-1">
                        <input
                          id="last_name"
                          name="last_name"
                          type="text"
                          required
                          value={formData.last_name}
                          onChange={handleChange}
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.last_name ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.last_name && (
                          <p className="mt-1 text-sm text-red-600">{errors.last_name}</p>
                        )}
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
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.email ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.email && (
                          <p className="mt-1 text-sm text-red-600">{errors.email}</p>
                        )}
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
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.phone ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.phone && (
                          <p className="mt-1 text-sm text-red-600">{errors.phone}</p>
                        )}
                      </div>
                    </div>
                  </div>
                </form>
              ) : currentStep === 1 ? (
                <form>
                  <div className="space-y-6">
                    <div>
                      <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                        Username
                      </label>
                      <div className="mt-1">
                        <input
                          id="username"
                          name="username"
                          type="text"
                          required
                          value={formData.username}
                          onChange={handleChange}
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.username ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.username && (
                          <p className="mt-1 text-sm text-red-600">{errors.username}</p>
                        )}
                      </div>
                    </div>

                    <div>
                      <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                        Password
                      </label>
                      <div className="mt-1">
                        <input
                          id="password"
                          name="password"
                          type="password"
                          required
                          value={formData.password}
                          onChange={handleChange}
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.password ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.password && (
                          <p className="mt-1 text-sm text-red-600">{errors.password}</p>
                        )}
                      </div>
                    </div>

                    <div>
                      <label htmlFor="confirm_password" className="block text-sm font-medium text-gray-700">
                        Confirm Password
                      </label>
                      <div className="mt-1">
                        <input
                          id="confirm_password"
                          name="confirm_password"
                          type="password"
                          required
                          value={formData.confirm_password}
                          onChange={handleChange}
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.confirm_password ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.confirm_password && (
                          <p className="mt-1 text-sm text-red-600">{errors.confirm_password}</p>
                        )}
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
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.bvn ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.bvn && (
                          <p className="mt-1 text-sm text-red-600">{errors.bvn}</p>
                        )}
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
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.nin ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.nin && (
                          <p className="mt-1 text-sm text-red-600">{errors.nin}</p>
                        )}
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
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.date_of_birth ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.date_of_birth && (
                          <p className="mt-1 text-sm text-red-600">{errors.date_of_birth}</p>
                        )}
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
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.address ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.address && (
                          <p className="mt-1 text-sm text-red-600">{errors.address}</p>
                        )}
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
                          className={`appearance-none block w-full px-3 py-2 border ${
                            errors.occupation ? 'border-red-300' : 'border-gray-300'
                          } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                        />
                        {errors.occupation && (
                          <p className="mt-1 text-sm text-red-600">{errors.occupation}</p>
                        )}
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
                  disabled={isSubmitting}
                  className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isSubmitting ? 'Processing...' : currentStep < steps.length - 1 ? 'Next' : 'Create Account'}
                  {!isSubmitting && <ChevronRight className="ml-2 -mr-1 h-5 w-5" />}
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
