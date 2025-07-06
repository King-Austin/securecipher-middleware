import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

// Auth Context
import { AuthProvider, useAuth } from './context/AuthContext';

// Layouts
import Layout from './components/layout/Layout';

// Common Components
import ProtectedRoute from './components/common/ProtectedRoute';

// Pages
import Registration from './pages/Registration';
import Login from './pages/Login';
import PINSetup from './pages/PINSetup';
import Dashboard from './pages/Dashboard';
import SendMoney from './pages/SendMoney';
import SecurityDetails from './pages/SecurityDetails';
import Settings from './pages/Settings';
import NotFound from './pages/NotFound';
import ServerError from './pages/ServerError';

// Error Handling
import ErrorBoundary from './components/common/ErrorBoundary';

// Styles
import './App.css';
import SecureOnboardingForm from './context/SecureOnboardingForm';

function AppRoutes() {
  const { isAuthenticated } = useAuth();

  return (
    <Routes>
      {/* Root redirect based on authentication */}
      <Route path="/" element={isAuthenticated ? <Navigate to="/dashboard" /> : <Navigate to="/login" />} />
      
      {/* Public routes */}
      <Route path="/register" element={<Registration />} />
      <Route path="/login" element={<SecureOnboardingForm />} /> 
      <Route path="/pin-setup" element={<PINSetup />} />
      
      {/* Protected routes with Layout */}
      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={
          <Layout>
            <Dashboard />
          </Layout>
        } />
        <Route path="/send-money" element={
          <Layout>
            <SendMoney />
          </Layout>
        } />
        <Route path="/security" element={
          <Layout>
            <SecurityDetails />
          </Layout>
        } />
        <Route path="/settings" element={
          <Layout>
            <Settings />
          </Layout>
        } />
        
        {/* Placeholder routes for future features */}
        <Route path="/cards" element={
          <Layout>
            <div className="p-6 text-center">
              <h1 className="text-2xl font-semibold text-gray-800 mb-4">My Cards</h1>
              <p className="text-gray-600">This feature is coming soon.</p>
            </div>
          </Layout>
        } />
        <Route path="/transactions" element={
          <Layout>
            <div className="p-6 text-center">
              <h1 className="text-2xl font-semibold text-gray-800 mb-4">Transactions</h1>
              <p className="text-gray-600">This feature is coming soon.</p>
            </div>
          </Layout>
        } />
      </Route>
      
      {/* Error routes */}
      <Route path="/server-error" element={<ServerError />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <Router>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </Router>
    </ErrorBoundary>
  );
}

export default App;
