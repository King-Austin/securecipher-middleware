import { useState } from 'react';
import { Lock, Shield, AlertTriangle, ChevronRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function SecuritySettings() {
  const [formData, setFormData] = useState({
    allow_biometric: true,
    two_factor_auth: true,
    login_notifications: true,
    device_management: true
  });
  const navigate = useNavigate();
  
  const handleToggle = (name) => {
    setFormData(prev => ({ ...prev, [name]: !prev[name] }));
  };
  
  const navigateToResetPin = () => {
    // In a real app, navigate to PIN reset page
    alert('Navigate to PIN reset page');
  };
  
  const navigateToDevices = () => {
    // In a real app, navigate to devices page
    alert('Navigate to devices page');
  };

  return (
    <div>
      <h2 className="text-lg font-medium text-gray-800 mb-4">Security Settings</h2>
      
      <div className="space-y-6">
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
          <div className="flex">
            <div className="flex-shrink-0">
              <AlertTriangle className="h-5 w-5 text-yellow-400" />
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-yellow-800">Security Notice</h3>
              <div className="mt-2 text-sm text-yellow-700">
                <p>Keeping your account secure is a priority. We recommend enabling all security features.</p>
              </div>
            </div>
          </div>
        </div>
        
        <div className="border-b border-gray-200 pb-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-md font-medium text-gray-800">Transaction PIN</h3>
              <p className="text-sm text-gray-500">Manage your 6-digit transaction PIN</p>
            </div>
            <button 
              onClick={navigateToResetPin}
              className="flex items-center text-sm text-green-600 hover:text-green-700"
            >
              Change PIN
              <ChevronRight className="h-4 w-4 ml-1" />
            </button>
          </div>
        </div>
        
        <div className="border-b border-gray-200 pb-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-md font-medium text-gray-800">Biometric Authentication</h3>
              <p className="text-sm text-gray-500">Use fingerprint or face ID to authenticate transactions</p>
            </div>
            <div className="relative inline-block w-10 mr-2 align-middle">
              <input 
                type="checkbox"
                id="toggle-biometric"
                name="allow_biometric"
                checked={formData.allow_biometric}
                onChange={() => handleToggle('allow_biometric')}
                className="sr-only"
              />
              <label
                htmlFor="toggle-biometric"
                className={`block h-6 w-10 rounded-full ${formData.allow_biometric ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
              >
                <span 
                  className={`absolute left-0.5 top-0.5 bg-white border-2 ${formData.allow_biometric ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                ></span>
              </label>
            </div>
          </div>
        </div>
        
        <div className="border-b border-gray-200 pb-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-md font-medium text-gray-800">Two-Factor Authentication</h3>
              <p className="text-sm text-gray-500">Require additional verification for logins</p>
            </div>
            <div className="relative inline-block w-10 mr-2 align-middle">
              <input 
                type="checkbox"
                id="toggle-tfa"
                name="two_factor_auth"
                checked={formData.two_factor_auth}
                onChange={() => handleToggle('two_factor_auth')}
                className="sr-only"
              />
              <label
                htmlFor="toggle-tfa"
                className={`block h-6 w-10 rounded-full ${formData.two_factor_auth ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
              >
                <span 
                  className={`absolute left-0.5 top-0.5 bg-white border-2 ${formData.two_factor_auth ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                ></span>
              </label>
            </div>
          </div>
        </div>
        
        <div className="border-b border-gray-200 pb-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-md font-medium text-gray-800">Login Notifications</h3>
              <p className="text-sm text-gray-500">Get notified when your account is accessed</p>
            </div>
            <div className="relative inline-block w-10 mr-2 align-middle">
              <input 
                type="checkbox"
                id="toggle-notifications"
                name="login_notifications"
                checked={formData.login_notifications}
                onChange={() => handleToggle('login_notifications')}
                className="sr-only"
              />
              <label
                htmlFor="toggle-notifications"
                className={`block h-6 w-10 rounded-full ${formData.login_notifications ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
              >
                <span 
                  className={`absolute left-0.5 top-0.5 bg-white border-2 ${formData.login_notifications ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                ></span>
              </label>
            </div>
          </div>
        </div>
        
        <div>
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-md font-medium text-gray-800">Device Management</h3>
              <p className="text-sm text-gray-500">View and manage devices with access to your account</p>
            </div>
            <button 
              onClick={navigateToDevices}
              className="flex items-center text-sm text-green-600 hover:text-green-700"
            >
              View Devices
              <ChevronRight className="h-4 w-4 ml-1" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
