import { ArrowUpRight, ArrowDownLeft, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function RecentTransactions() {
  const transactions = [
    {
      id: 'tx1',
      type: 'credit',
      amount: 150000,
      description: 'Salary Payment',
      date: '20 Jun 2025',
      recipient: 'Employer Inc.',
      status: 'completed'
    },
    {
      id: 'tx2',
      type: 'debit',
      amount: 25000,
      description: 'Rent Payment',
      date: '15 Jun 2025',
      recipient: 'Landlord Properties',
      status: 'completed'
    },
    {
      id: 'tx3',
      type: 'debit',
      amount: 12500,
      description: 'Grocery Shopping',
      date: '10 Jun 2025',
      recipient: 'Shoprite',
      status: 'completed'
    },
    {
      id: 'tx4',
      type: 'credit',
      amount: 50000,
      description: 'Refund',
      date: '05 Jun 2025',
      recipient: 'Online Store',
      status: 'completed'
    }
  ];

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <div className="flex items-center justify-between p-6 border-b border-gray-200">
        <h2 className="text-lg font-medium text-gray-800">Recent Transactions</h2>
        <Link to="/transactions" className="text-sm text-green-600 hover:text-green-700 flex items-center">
          See All
          <ChevronRight className="h-4 w-4 ml-1" />
        </Link>
      </div>
      
      <div className="divide-y divide-gray-200">
        {transactions.map((transaction) => (
          <div key={transaction.id} className="p-4 hover:bg-gray-50">
            <div className="flex items-center">
              <div className={`rounded-full p-2 mr-4 ${
                transaction.type === 'credit' 
                  ? 'bg-green-100 text-green-600' 
                  : 'bg-red-100 text-red-600'
              }`}>
                {transaction.type === 'credit' 
                  ? <ArrowDownLeft className="h-5 w-5" /> 
                  : <ArrowUpRight className="h-5 w-5" />
                }
              </div>
              
              <div className="flex-1">
                <p className="font-medium text-gray-800">{transaction.description}</p>
                <p className="text-sm text-gray-500">{transaction.recipient}</p>
              </div>
              
              <div className="text-right">
                <p className={`font-medium ${
                  transaction.type === 'credit' 
                    ? 'text-green-600' 
                    : 'text-red-600'
                }`}>
                  {transaction.type === 'credit' ? '+' : '-'}₦{transaction.amount.toLocaleString()}
                </p>
                <p className="text-xs text-gray-500">{transaction.date}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
