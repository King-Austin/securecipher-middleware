import AccountSummary from '../components/dashboard/AccountSummary';
import QuickActions from '../components/dashboard/QuickActions';
import RecentTransactions from '../components/dashboard/RecentTransactions';
import SpendingInsights from '../components/dashboard/SpendingInsights';

export default function Dashboard() {
  return (
    <div>
      <h1 className="text-2xl font-semibold text-gray-800">Dashboard</h1>
      <p className="text-gray-600 mb-6">Welcome back, Samuel</p>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <div className="md:col-span-2">
          <AccountSummary />
        </div>
        <div>
          <QuickActions />
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RecentTransactions />
        </div>
        <div>
          <SpendingInsights />
        </div>
      </div>
    </div>
  );
}
