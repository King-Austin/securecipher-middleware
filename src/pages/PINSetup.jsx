import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Check, AlertCircle } from 'lucide-react';
import { SecureKeyManager } from '../utils/SecureKeyManager';

export default function PINSetup() {
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const navigate = useNavigate();

  const handlePinChange = (e) => {
    const value = e.target.value.replace(/[^0-9]/g, '');
    if (value.length <= 6) {
      setPin(value);
      setError('');
    }
  };

  const handleConfirmPinChange = (e) => {
    const value = e.target.value.replace(/[^0-9]/g, '');
    if (value.length <= 6) {
      setConfirmPin(value);
      setError('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (pin.length !== 6) {
      setError('PIN must be 6 digits');
      return;
    }
    
    if (pin !== confirmPin) {
      setError('PINs do not match');
      return;
    }
    
    try {
      setIsLoading(true);
      
      // Generate ECDSA key pair
      const keyPair = await SecureKeyManager.generateKeyPair();
      
      // Export public key (to be sent to server)
      const publicKeyBase64 = await SecureKeyManager.exportPublicKey(keyPair.publicKey);
      
      // Encrypt private key with PIN
      const encryptedKey = await SecureKeyManager.encryptPrivateKey(keyPair.privateKey, pin);
      
      // Store encrypted key in IndexedDB
      await SecureKeyManager.storeEncryptedKey(encryptedKey);
      
      // In a real application, you would send publicKeyBase64 to your server here
      console.log('Public key generated:', publicKeyBase64);
      
      setIsSuccess(true);
      
      // Navigate to dashboard after 2 seconds
      setTimeout(() => {
        navigate('/dashboard');
      }, 2000);
      
    } catch (err) {
      console.error('Error during key setup:', err);
      setError('An error occurred during setup. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-gray-50">
      <div className="flex-1 flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div className="mx-auto w-full max-w-md">
          <div className="text-center">
            <h2 className="text-3xl font-extrabold text-gray-900">
              Secure Your Account
            </h2>
            <p className="mt-2 text-sm text-gray-600">
              Set up your 6-digit transaction PIN
            </p>
          </div>

          <div className="mt-8">
            <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
              {isSuccess ? (
                <div className="text-center">
                  <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                    <Check className="h-6 w-6 text-green-600" />
                  </div>
                  <h3 className="mt-3 text-lg font-medium text-gray-900">Setup complete!</h3>
                  <p className="mt-2 text-sm text-gray-500">
                    Your secure keys have been generated and encrypted.
                  </p>
                  <p className="mt-1 text-sm text-gray-500">
                    Redirecting to your dashboard...
                  </p>
                </div>
              ) : (
                <form className="space-y-6" onSubmit={handleSubmit}>
                  <div className="flex justify-center">
                    <div className="rounded-full bg-green-100 p-3">
                      <Shield className="h-8 w-8 text-green-600" />
                    </div>
                  </div>
                  
                  <div>
                    <label htmlFor="pin" className="block text-sm font-medium text-gray-700">
                      Create 6-digit PIN
                    </label>
                    <div className="mt-1">
                      <input
                        id="pin"
                        name="pin"
                        type="password"
                        inputMode="numeric"
                        pattern="[0-9]*"
                        maxLength="6"
                        placeholder="******"
                        required
                        value={pin}
                        onChange={handlePinChange}
                        className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                      />
                    </div>
                    <p className="mt-1 text-xs text-gray-500">
                      This PIN will be used to authorize transactions
                    </p>
                  </div>

                  <div>
                    <label htmlFor="confirmPin" className="block text-sm font-medium text-gray-700">
                      Confirm PIN
                    </label>
                    <div className="mt-1">
                      <input
                        id="confirmPin"
                        name="confirmPin"
                        type="password"
                        inputMode="numeric"
                        pattern="[0-9]*"
                        maxLength="6"
                        placeholder="******"
                        required
                        value={confirmPin}
                        onChange={handleConfirmPinChange}
                        className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
                      />
                    </div>
                  </div>

                  {error && (
                    <div className="rounded-md bg-red-50 p-4">
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

                  <div className="mt-4 bg-gray-50 p-3 rounded-md">
                    <h4 className="text-sm font-medium text-gray-700">Your PIN will:</h4>
                    <ul className="mt-2 text-xs text-gray-500 space-y-1">
                      <li className="flex items-center">
                        <Check className="h-4 w-4 text-green-500 mr-2" />
                        Encrypt your private keys stored on this device
                      </li>
                      <li className="flex items-center">
                        <Check className="h-4 w-4 text-green-500 mr-2" />
                        Be required to authorize all transactions
                      </li>
                      <li className="flex items-center">
                        <Check className="h-4 w-4 text-green-500 mr-2" />
                        Never be stored on our servers
                      </li>
                    </ul>
                  </div>

                  <div>
                    <button
                      type="submit"
                      disabled={isLoading}
                      className={`w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 ${
                        isLoading ? 'opacity-75 cursor-not-allowed' : ''
                      }`}
                    >
                      {isLoading ? 'Setting up...' : 'Set PIN & Complete Setup'}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
