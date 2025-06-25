import { PieChart, Home, ShoppingBag, Coffee } from 'lucide-react';

export default function SpendingInsights() {
  const categories = [
    { name: 'Housing', amount: 75000, percentage: 45, icon: <Home className="h-4 w-4" />, color: 'bg-blue-500' },
    { name: 'Shopping', amount: 40000, percentage: 25, icon: <ShoppingBag className="h-4 w-4" />, color: 'bg-purple-500' },
    { name: 'Food', amount: 30000, percentage: 18, icon: <Coffee className="h-4 w-4" />, color: 'bg-yellow-500' },
    { name: 'Others', amount: 20000, percentage: 12, icon: null, color: 'bg-gray-500' },
  ];

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center mb-4">
        <PieChart className="h-5 w-5 text-gray-700 mr-2" />
        <h2 className="text-lg font-medium text-gray-800">Spending Insights</h2>
      </div>
      
      <div className="space-y-4">
        {categories.map((category, index) => (
          <div key={index}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center">
                {category.icon && (
                  <div className="mr-2 text-gray-600">
                    {category.icon}
                  </div>
                )}
                <span className="text-sm text-gray-700">{category.name}</span>
              </div>
              <span className="text-sm font-medium text-gray-800">₦{category.amount.toLocaleString()}</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className={`${category.color} h-2 rounded-full`} 
                style={{ width: `${category.percentage}%` }}
              ></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
