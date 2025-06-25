import { Link } from 'react-router-dom';
import { ServerCrash } from 'lucide-react';

export default function ServerError() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-50 px-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-md p-8 text-center">
        <div className="flex justify-center mb-4">
          <ServerCrash className="h-16 w-16 text-red-500" />
        </div>
        <h1 className="text-3xl font-bold text-gray-800 mb-2">500</h1>
        <h2 className="text-xl font-semibold text-gray-700 mb-4">Server Error</h2>
        <p className="text-gray-600 mb-6">
          Sorry, something went wrong on our server. We're working to fix the issue.
        </p>
        <Link
          to="/dashboard"
          className="w-full inline-block py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
        >
          Return to Dashboard
        </Link>
      </div>
    </div>
  );
}
