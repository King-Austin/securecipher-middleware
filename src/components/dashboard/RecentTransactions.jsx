import { useState, useEffect } from 'react';
import { ArrowUpRight, ArrowDownLeft, ChevronRight, RefreshCw } from 'lucide-react';
import { Link } from 'react-router-dom';
import api from '../../services/api';

export default function RecentTransactions() {
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Fetch transactions from API
    fetchTransactions();
  }, []);

  const fetchTransactions = async () => {
    try {
      setLoading(true);
      const data = await api.transaction.getTransactions();
      // Sort by date (newest first) and limit to 5
      const sortedTransactions = data
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
        .slice(0, 5);
      setTransactions(sortedTransactions);
    } catch (err) {
      console.error('Error fetching transactions:', err);
      setError('Failed to load transactions');
    } finally {
      setLoading(false);
    }
  };

  // Format date from ISO string to "15 Jun 2025" format
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'short',
      year: 'numeric'
    });
  };

  // Format amount with Naira symbol
  const formatAmount = (amount) => {
    return new Intl.NumberFormat('en-NG', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(amount);
  };

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <div className="flex items-center justify-between p-6 border-b border-gray-200">
        <h2 className="text-lg font-medium text-gray-800">Recent Transactions</h2>
        <div className="flex items-center">
          <button 
            onClick={fetchTransactions} 
            className="mr-2 text-gray-500 hover:text-gray-700"
            title="Refresh transactions"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
          <Link to="/transactions" className="text-sm text-green-600 hover:text-green-700 flex items-center">
            See All
            <ChevronRight className="h-4 w-4 ml-1" />
          </Link>
        </div>
      </div>
      
      <div className="divide-y divide-gray-200">
        {loading ? (
          <div className="p-8 text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-green-500 mb-2"></div>
            <p className="text-gray-500">Loading transactions...</p>
          </div>
        ) : error ? (
          <div className="p-8 text-center">
            <p className="text-red-500">{error}</p>
            <button 
              onClick={fetchTransactions}
              className="mt-2 text-sm text-green-600 hover:text-green-700"
            >
              Try Again
            </button>
          </div>
        ) : transactions.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-gray-500">No transactions yet</p>
          </div>
        ) : (
          transactions.map((transaction) => (
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
                  <p className="font-medium text-gray-800">{transaction.description || 'Transaction'}</p>
                  <p className="text-sm text-gray-500">
                    {transaction.type === 'credit' 
                      ? 'From: ' + (transaction.recipient_name || 'Unknown') 
                      : 'To: ' + (transaction.recipient_name || 'Unknown')}
                  </p>
                </div>
                
                <div className="text-right">
                  <p className={`font-medium ${
                    transaction.type === 'credit' 
                      ? 'text-green-600' 
                      : 'text-red-600'
                  }`}>
                    {transaction.type === 'credit' ? '+' : '-'}₦{formatAmount(transaction.amount)}
                  </p>
                  <p className="text-xs text-gray-500">{formatDate(transaction.created_at)}</p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
