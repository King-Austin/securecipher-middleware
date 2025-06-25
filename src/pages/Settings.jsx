import { useState } from 'react';
import EditProfile from '../components/settings/EditProfile';
import SecuritySettings from '../components/settings/SecuritySettings';
import NotificationSettings from '../components/settings/NotificationSettings';

export default function Settings() {
  const [activeTab, setActiveTab] = useState('profile');

  const tabs = [
    { id: 'profile', label: 'Profile' },
    { id: 'security', label: 'Security' },
    { id: 'notifications', label: 'Notifications' },
  ];

  return (
    <div>
      <h1 className="text-2xl font-semibold text-gray-800 mb-6">Settings</h1>
      
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="border-b border-gray-200">
          <nav className="flex -mb-px">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-4 px-6 text-center border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-green-500 text-green-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
        
        <div className="p-6">
          {activeTab === 'profile' && <EditProfile />}
          {activeTab === 'security' && <SecuritySettings />}
          {activeTab === 'notifications' && <NotificationSettings />}
        </div>
      </div>
    </div>
  );
}
