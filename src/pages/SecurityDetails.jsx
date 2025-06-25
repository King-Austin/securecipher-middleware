import { useState, useEffect } from 'react';
import { Shield, Key, Lock, Copy, Check } from 'lucide-react';
import { SecureKeyManager } from '../utils/SecureKeyManager';

export default function SecurityDetails() {
  const [publicKey, setPublicKey] = useState('');
  const [copied, setCopied] = useState(false);
  
  useEffect(() => {
    const fetchPublicKey = async () => {
      try {
        // In a real app, this would be fetched from your server
        // Here we're simulating by generating a new key
        const keyPair = await SecureKeyManager.generateKeyPair();
        const publicKeyBase64 = await SecureKeyManager.exportPublicKey(keyPair.publicKey);
        
        // Show only a portion of the key for UI display
        setPublicKey(formatPublicKey(publicKeyBase64));
      } catch (error) {
        console.error('Error fetching public key:', error);
      }
    };
    
    fetchPublicKey();
  }, []);
  
  const formatPublicKey = (key) => {
    if (!key) return '';
    const start = key.substring(0, 20);
    const end = key.substring(key.length - 20);
    return `${start}...${end}`;
  };
  
  const copyPublicKey = () => {
    navigator.clipboard.writeText(publicKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold text-gray-800 mb-6">Security Center</h1>
      
      <div className="bg-white rounded-lg shadow overflow-hidden mb-6">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center mb-4">
            <Shield className="h-6 w-6 text-green-600 mr-2" />
            <h2 className="text-lg font-medium text-gray-800">Security Overview</h2>
          </div>
          
          <p className="text-gray-600 mb-4">
            Your account is protected with client-side cryptography. Your private key is securely stored on your device and is never shared with our servers.
          </p>
          
          <div className="bg-green-50 rounded-md p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <Check className="h-5 w-5 text-green-600" />
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-green-800">Your account is secure</h3>
                <div className="mt-2 text-sm text-green-700">
                  <p>Your transactions are signed with your private key which is encrypted with your PIN and stored only on this device.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center mb-4">
            <Key className="h-6 w-6 text-green-600 mr-2" />
            <h2 className="text-lg font-medium text-gray-800">Your Public Key</h2>
          </div>
          
          <p className="text-gray-600 mb-4">
            This is your public verification key. It's used to verify your transactions but cannot be used to access your funds.
          </p>
          
          <div className="bg-gray-50 p-3 rounded-md flex items-center justify-between mb-4">
            <code className="text-xs text-gray-700 font-mono break-all">
              {publicKey || 'Loading...'}
            </code>
            <button 
              onClick={copyPublicKey}
              className="ml-2 p-1 rounded-md hover:bg-gray-200 focus:outline-none"
              aria-label="Copy public key"
            >
              {copied ? <Check className="h-5 w-5 text-green-600" /> : <Copy className="h-5 w-5 text-gray-600" />}
            </button>
          </div>
        </div>
        
        <div className="p-6">
          <div className="flex items-center mb-4">
            <Lock className="h-6 w-6 text-green-600 mr-2" />
            <h2 className="text-lg font-medium text-gray-800">Verified Information</h2>
          </div>
          
          <div className="space-y-4">
            <div className="flex justify-between">
              <span className="text-sm text-gray-600">BVN Status</span>
              <span className="text-sm font-medium text-green-600">Verified</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-600">NIN Status</span>
              <span className="text-sm font-medium text-green-600">Verified</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-600">Email</span>
              <span className="text-sm font-medium text-green-600">Verified</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-600">Phone Number</span>
              <span className="text-sm font-medium text-green-600">Verified</span>
            </div>
          </div>
        </div>
      </div>
      
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6">
        <h3 className="text-lg font-medium text-yellow-800 mb-2">Important Security Notice</h3>
        <p className="text-sm text-yellow-700 mb-4">
          Your private key is stored securely and encrypted on your device and is never accessible by the bank. 
          It is encrypted with your PIN and used to sign transactions.
        </p>
        <ul className="text-sm text-yellow-700 space-y-2">
          <li className="flex items-start">
            <span className="mr-2">•</span>
            <span>Never share your PIN with anyone, including Secure Cipher Bank staff.</span>
          </li>
          <li className="flex items-start">
            <span className="mr-2">•</span>
            <span>Always ensure you're on the official Secure Cipher Bank website before entering your PIN.</span>
          </li>
          <li className="flex items-start">
            <span className="mr-2">•</span>
            <span>If you get a new device, you'll need to set up a new key pair. Contact support for assistance.</span>
          </li>
        </ul>
      </div>
    </div>
  );
}
