import { useState } from 'react';
import { ArrowRight, Building, AlertCircle, Check } from 'lucide-react';
import { SecureKeyManager } from '../utils/SecureKeyManager';

export default function SendMoney() {
  const [step, setStep] = useState(1);
  const [transactionData, setTransactionData] = useState({
    recipient_account: '',
    recipient_bank: '',
    recipient_name: '',
    amount: '',
    description: ''
  });
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  
  const banks = [
    'Access Bank',
    'First Bank of Nigeria',
    'Guaranty Trust Bank',
    'United Bank for Africa',
    'Zenith Bank',
    'Fidelity Bank',
    'Ecobank Nigeria',
    'Union Bank of Nigeria',
    'Sterling Bank',
    'Wema Bank'
  ];
  
  const handleChange = (e) => {
    const { name, value } = e.target;
    setTransactionData(prev => ({ ...prev, [name]: value }));
    setError('');
  };
  
  const handlePinChange = (e) => {
    const value = e.target.value.replace(/[^0-9]/g, '');
    if (value.length <= 6) {
      setPin(value);
      setError('');
    }
  };
  
  const handleNextStep = () => {
    if (step === 1) {
      // Validate first step fields
      if (!transactionData.recipient_account || !transactionData.recipient_bank) {
        setError('Please fill in all required fields');
        return;
      }
      
      // In a real app, you would verify the account here
      // and populate the recipient_name
      setTransactionData(prev => ({
        ...prev,
        recipient_name: 'John Doe' // This would come from the bank's verification API
      }));
      
      setStep(2);
    } else if (step === 2) {
      // Validate second step fields
      if (!transactionData.amount || parseFloat(transactionData.amount) <= 0) {
        setError('Please enter a valid amount');
        return;
      }
      
      setStep(3);
    }
  };
  
  const handlePrevStep = () => {
    if (step > 1) {
      setStep(step - 1);
      setError('');
    }
  };
  
  const handleSubmit = async () => {
    if (pin.length !== 6) {
      setError('Please enter your 6-digit PIN');
      return;
    }
    
    try {
      setLoading(true);
      
      // In a real app, retrieve the encrypted key from IndexedDB
      // Here we're simulating by generating a new key
      const keyPair = await SecureKeyManager.generateKeyPair();
      
      // Create transaction payload
      const payload = JSON.stringify({
        ...transactionData,
        timestamp: new Date().toISOString(),
        reference: `TX${Date.now()}`
      });
      
      // Sign the transaction with the private key
      const signature = await SecureKeyManager.signData(keyPair.privateKey, payload);
      
      // In a real app, send this to your server:
      console.log('Transaction payload:', payload);
      console.log('Transaction signature:', signature);
      
      // Simulate API call delay
      setTimeout(() => {
        setLoading(false);
        setSuccess(true);
        
        // Reset after showing success
        setTimeout(() => {
          setStep(1);
          setTransactionData({
            recipient_account: '',
            recipient_bank: '',
            recipient_name: '',
            amount: '',
            description: ''
          });
          setPin('');
          setSuccess(false);
        }, 3000);
      }, 1500);
      
    } catch (err) {
      console.error('Error during transaction signing:', err);
      setError('An error occurred while processing your transaction. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold text-gray-800 mb-6">Send Money</h1>
      
      {success ? (
        <div className="bg-white rounded-lg shadow p-8 text-center">
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
            <Check className="h-6 w-6 text-green-600" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">Transfer Successful!</h3>
          <p className="text-gray-600 mb-4">
            You've sent ₦{parseFloat(transactionData.amount).toLocaleString()} to {transactionData.recipient_name}
          </p>
          <p className="text-sm text-gray-500">
            Transaction Reference: TX{Date.now()}
          </p>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          {/* Step indicator */}
          <div className="px-6 pt-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center">
                <div className={`flex items-center justify-center h-8 w-8 rounded-full ${
                  step >= 1 ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-600'
                }`}>
                  1
                </div>
                <div className="ml-2 text-sm font-medium text-gray-700">Recipient</div>
              </div>
              <div className="flex-1 h-0.5 mx-4 bg-gray-200"></div>
              <div className="flex items-center">
                <div className={`flex items-center justify-center h-8 w-8 rounded-full ${
                  step >= 2 ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-600'
                }`}>
                  2
                </div>
                <div className="ml-2 text-sm font-medium text-gray-700">Amount</div>
              </div>
              <div className="flex-1 h-0.5 mx-4 bg-gray-200"></div>
              <div className="flex items-center">
                <div className={`flex items-center justify-center h-8 w-8 rounded-full ${
                  step >= 3 ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-600'
                }`}>
                  3
                </div>
                <div className="ml-2 text-sm font-medium text-gray-700">Confirm</div>
              </div>
            </div>
          </div>
          
          <div className="p-6 border-t border-gray-200">
            {step === 1 && (
              <div>
                <h2 className="text-lg font-medium text-gray-800 mb-4">Recipient Details</h2>
                
                <div className="space-y-4">
                  <div>
                    <label htmlFor="recipient_account" className="block text-sm font-medium text-gray-700 mb-1">
                      Account Number
                    </label>
                    <input
                      type="text"
                      id="recipient_account"
                      name="recipient_account"
                      value={transactionData.recipient_account}
                      onChange={handleChange}
                      placeholder="Enter 10-digit account number"
                      className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                    />
                  </div>
                  
                  <div>
                    <label htmlFor="recipient_bank" className="block text-sm font-medium text-gray-700 mb-1">
                      Bank Name
                    </label>
                    <select
                      id="recipient_bank"
                      name="recipient_bank"
                      value={transactionData.recipient_bank}
                      onChange={handleChange}
                      className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                    >
                      <option value="">Select bank</option>
                      {banks.map((bank) => (
                        <option key={bank} value={bank}>{bank}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>
            )}
            
            {step === 2 && (
              <div>
                <h2 className="text-lg font-medium text-gray-800 mb-4">Transfer Amount</h2>
                
                <div className="mb-4">
                  <div className="bg-gray-50 p-3 rounded-md flex items-center mb-4">
                    <Building className="h-5 w-5 text-gray-400 mr-2" />
                    <div>
                      <p className="text-sm font-medium text-gray-800">{transactionData.recipient_name}</p>
                      <p className="text-xs text-gray-500">
                        {transactionData.recipient_account} • {transactionData.recipient_bank}
                      </p>
                    </div>
                  </div>
                  
                  <div className="space-y-4">
                    <div>
                      <label htmlFor="amount" className="block text-sm font-medium text-gray-700 mb-1">
                        Amount (NGN)
                      </label>
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                          <span className="text-gray-500 sm:text-sm">₦</span>
                        </div>
                        <input
                          type="number"
                          id="amount"
                          name="amount"
                          value={transactionData.amount}
                          onChange={handleChange}
                          placeholder="0.00"
                          className="appearance-none block w-full pl-7 pr-12 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                        />
                      </div>
                    </div>
                    
                    <div>
                      <label htmlFor="description" className="block text-sm font-medium text-gray-700 mb-1">
                        Description (Optional)
                      </label>
                      <input
                        type="text"
                        id="description"
                        name="description"
                        value={transactionData.description}
                        onChange={handleChange}
                        placeholder="What's this transfer for?"
                        className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                      />
                    </div>
                  </div>
                </div>
              </div>
            )}
            
            {step === 3 && (
              <div>
                <h2 className="text-lg font-medium text-gray-800 mb-4">Confirm Transfer</h2>
                
                <div className="bg-gray-50 p-4 rounded-md mb-6">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs text-gray-500">Recipient</p>
                      <p className="text-sm font-medium text-gray-800">{transactionData.recipient_name}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500">Bank</p>
                      <p className="text-sm font-medium text-gray-800">{transactionData.recipient_bank}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500">Account Number</p>
                      <p className="text-sm font-medium text-gray-800">{transactionData.recipient_account}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500">Amount</p>
                      <p className="text-sm font-medium text-gray-800">₦{parseFloat(transactionData.amount || 0).toLocaleString()}</p>
                    </div>
                    {transactionData.description && (
                      <div className="col-span-2">
                        <p className="text-xs text-gray-500">Description</p>
                        <p className="text-sm font-medium text-gray-800">{transactionData.description}</p>
                      </div>
                    )}
                  </div>
                </div>
                
                <div>
                  <label htmlFor="pin" className="block text-sm font-medium text-gray-700 mb-1">
                    Enter your 6-digit PIN to authorize
                  </label>
                  <input
                    type="password"
                    id="pin"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength="6"
                    placeholder="******"
                    value={pin}
                    onChange={handlePinChange}
                    className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    Your PIN will be used to decrypt your private key and sign this transaction.
                  </p>
                </div>
              </div>
            )}
            
            {error && (
              <div className="mt-4 rounded-md bg-red-50 p-4">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <AlertCircle className="h-5 w-5 text-red-400" />
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-red-800">{error}</h3>
                  </div>
                </div>
              </div>
            )}
            
            <div className="mt-6 flex justify-between">
              <button
                type="button"
                onClick={handlePrevStep}
                disabled={step === 1}
                className={`inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 ${
                  step === 1 ? 'opacity-50 cursor-not-allowed' : ''
                }`}
              >
                Back
              </button>
              
              {step < 3 ? (
                <button
                  type="button"
                  onClick={handleNextStep}
                  className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                >
                  Continue
                  <ArrowRight className="ml-2 -mr-1 h-5 w-5" />
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={loading}
                  className={`inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 ${
                    loading ? 'opacity-75 cursor-not-allowed' : ''
                  }`}
                >
                  {loading ? 'Processing...' : 'Send Money'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
