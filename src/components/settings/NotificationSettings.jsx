import { useState } from 'react';
import { Bell, Mail, Smartphone } from 'lucide-react';

export default function NotificationSettings() {
  const [emailSettings, setEmailSettings] = useState({
    transaction_alerts: true,
    security_alerts: true,
    marketing_emails: false,
    account_updates: true
  });
  
  const [pushSettings, setPushSettings] = useState({
    transaction_alerts: true,
    security_alerts: true,
    new_features: true,
    offers: false
  });
  
  const [smsSettings, setSmsSettings] = useState({
    transaction_alerts: true,
    security_alerts: true,
    marketing_messages: false
  });
  
  const handleEmailToggle = (name) => {
    setEmailSettings(prev => ({ ...prev, [name]: !prev[name] }));
  };
  
  const handlePushToggle = (name) => {
    setPushSettings(prev => ({ ...prev, [name]: !prev[name] }));
  };
  
  const handleSmsToggle = (name) => {
    setSmsSettings(prev => ({ ...prev, [name]: !prev[name] }));
  };

  return (
    <div>
      <h2 className="text-lg font-medium text-gray-800 mb-4">Notification Settings</h2>
      
      <div className="space-y-6">
        {/* Email Notifications */}
        <div className="border-b border-gray-200 pb-6">
          <div className="flex items-center mb-4">
            <Mail className="h-5 w-5 text-gray-400 mr-2" />
            <h3 className="text-md font-medium text-gray-800">Email Notifications</h3>
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Transaction Alerts</p>
                <p className="text-xs text-gray-500">Receive emails for all transactions</p>
              </div>
              <div className="relative inline-block w-10 mr-2 align-middle">
                <input 
                  type="checkbox"
                  id="email-transactions"
                  checked={emailSettings.transaction_alerts}
                  onChange={() => handleEmailToggle('transaction_alerts')}
                  className="sr-only"
                />
                <label
                  htmlFor="email-transactions"
                  className={`block h-6 w-10 rounded-full ${emailSettings.transaction_alerts ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
                >
                  <span 
                    className={`absolute left-0.5 top-0.5 bg-white border-2 ${emailSettings.transaction_alerts ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                  ></span>
                </label>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Security Alerts</p>
                <p className="text-xs text-gray-500">Receive emails about security updates</p>
              </div>
              <div className="relative inline-block w-10 mr-2 align-middle">
                <input 
                  type="checkbox"
                  id="email-security"
                  checked={emailSettings.security_alerts}
                  onChange={() => handleEmailToggle('security_alerts')}
                  className="sr-only"
                />
                <label
                  htmlFor="email-security"
                  className={`block h-6 w-10 rounded-full ${emailSettings.security_alerts ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
                >
                  <span 
                    className={`absolute left-0.5 top-0.5 bg-white border-2 ${emailSettings.security_alerts ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                  ></span>
                </label>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Marketing Emails</p>
                <p className="text-xs text-gray-500">Receive emails about promotions and offers</p>
              </div>
              <div className="relative inline-block w-10 mr-2 align-middle">
                <input 
                  type="checkbox"
                  id="email-marketing"
                  checked={emailSettings.marketing_emails}
                  onChange={() => handleEmailToggle('marketing_emails')}
                  className="sr-only"
                />
                <label
                  htmlFor="email-marketing"
                  className={`block h-6 w-10 rounded-full ${emailSettings.marketing_emails ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
                >
                  <span 
                    className={`absolute left-0.5 top-0.5 bg-white border-2 ${emailSettings.marketing_emails ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                  ></span>
                </label>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Account Updates</p>
                <p className="text-xs text-gray-500">Receive emails about account changes</p>
              </div>
              <div className="relative inline-block w-10 mr-2 align-middle">
                <input 
                  type="checkbox"
                  id="email-account"
                  checked={emailSettings.account_updates}
                  onChange={() => handleEmailToggle('account_updates')}
                  className="sr-only"
                />
                <label
                  htmlFor="email-account"
                  className={`block h-6 w-10 rounded-full ${emailSettings.account_updates ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
                >
                  <span 
                    className={`absolute left-0.5 top-0.5 bg-white border-2 ${emailSettings.account_updates ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                  ></span>
                </label>
              </div>
            </div>
          </div>
        </div>
        
        {/* Push Notifications */}
        <div className="border-b border-gray-200 pb-6">
          <div className="flex items-center mb-4">
            <Bell className="h-5 w-5 text-gray-400 mr-2" />
            <h3 className="text-md font-medium text-gray-800">Push Notifications</h3>
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Transaction Alerts</p>
                <p className="text-xs text-gray-500">Get push notifications for transactions</p>
              </div>
              <div className="relative inline-block w-10 mr-2 align-middle">
                <input 
                  type="checkbox"
                  id="push-transactions"
                  checked={pushSettings.transaction_alerts}
                  onChange={() => handlePushToggle('transaction_alerts')}
                  className="sr-only"
                />
                <label
                  htmlFor="push-transactions"
                  className={`block h-6 w-10 rounded-full ${pushSettings.transaction_alerts ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
                >
                  <span 
                    className={`absolute left-0.5 top-0.5 bg-white border-2 ${pushSettings.transaction_alerts ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                  ></span>
                </label>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Security Alerts</p>
                <p className="text-xs text-gray-500">Get push notifications for security events</p>
              </div>
              <div className="relative inline-block w-10 mr-2 align-middle">
                <input 
                  type="checkbox"
                  id="push-security"
                  checked={pushSettings.security_alerts}
                  onChange={() => handlePushToggle('security_alerts')}
                  className="sr-only"
                />
                <label
                  htmlFor="push-security"
                  className={`block h-6 w-10 rounded-full ${pushSettings.security_alerts ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
                >
                  <span 
                    className={`absolute left-0.5 top-0.5 bg-white border-2 ${pushSettings.security_alerts ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                  ></span>
                </label>
              </div>
            </div>
          </div>
        </div>
        
        {/* SMS Notifications */}
        <div>
          <div className="flex items-center mb-4">
            <Smartphone className="h-5 w-5 text-gray-400 mr-2" />
            <h3 className="text-md font-medium text-gray-800">SMS Notifications</h3>
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Transaction Alerts</p>
                <p className="text-xs text-gray-500">Get SMS alerts for all transactions</p>
              </div>
              <div className="relative inline-block w-10 mr-2 align-middle">
                <input 
                  type="checkbox"
                  id="sms-transactions"
                  checked={smsSettings.transaction_alerts}
                  onChange={() => handleSmsToggle('transaction_alerts')}
                  className="sr-only"
                />
                <label
                  htmlFor="sms-transactions"
                  className={`block h-6 w-10 rounded-full ${smsSettings.transaction_alerts ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
                >
                  <span 
                    className={`absolute left-0.5 top-0.5 bg-white border-2 ${smsSettings.transaction_alerts ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                  ></span>
                </label>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Security Alerts</p>
                <p className="text-xs text-gray-500">Get SMS alerts for security events</p>
              </div>
              <div className="relative inline-block w-10 mr-2 align-middle">
                <input 
                  type="checkbox"
                  id="sms-security"
                  checked={smsSettings.security_alerts}
                  onChange={() => handleSmsToggle('security_alerts')}
                  className="sr-only"
                />
                <label
                  htmlFor="sms-security"
                  className={`block h-6 w-10 rounded-full ${smsSettings.security_alerts ? 'bg-green-600' : 'bg-gray-300'} cursor-pointer transition-colors duration-200`}
                >
                  <span 
                    className={`absolute left-0.5 top-0.5 bg-white border-2 ${smsSettings.security_alerts ? 'border-green-600 translate-x-4' : 'border-gray-300'} rounded-full h-5 w-5 transition duration-200 transform`}
                  ></span>
                </label>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
