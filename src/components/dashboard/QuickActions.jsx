import { Send, CreditCard, Smartphone, Download } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function QuickActions() {
  const actions = [
    { 
      icon: <Send className="h-5 w-5" />, 
      label: 'Send Money', 
      color: 'bg-blue-100 text-blue-600', 
      link: '/send-money' 
    },
    { 
      icon: <CreditCard className="h-5 w-5" />, 
      label: 'Cards', 
      color: 'bg-purple-100 text-purple-600', 
      link: '/cards' 
    },
    { 
      icon: <Smartphone className="h-5 w-5" />, 
      label: 'Airtime', 
      color: 'bg-yellow-100 text-yellow-600', 
      link: '/airtime' 
    },
    { 
      icon: <Download className="h-5 w-5" />, 
      label: 'Download', 
      color: 'bg-green-100 text-green-600', 
      link: '/statements' 
    },
  ];

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-lg font-medium text-gray-800 mb-4">Quick Actions</h2>
      
      <div className="grid grid-cols-2 gap-3">
        {actions.map((action, index) => (
          <Link 
            key={index} 
            to={action.link}
            className="flex flex-col items-center justify-center p-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors"
          >
            <div className={`rounded-full p-2 ${action.color} mb-2`}>
              {action.icon}
            </div>
            <span className="text-sm text-gray-700">{action.label}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
