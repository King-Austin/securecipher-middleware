import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Home, 
  Send, 
  CreditCard, 
  ClipboardList, 
  Shield, 
  Settings, 
  LogOut, 
  Menu, 
  X 
} from 'lucide-react';

export default function Layout({ children }) {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const location = useLocation();
  
  const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: <Home className="w-5 h-5" /> },
    { path: '/send-money', label: 'Send Money', icon: <Send className="w-5 h-5" /> },
    { path: '/cards', label: 'My Cards', icon: <CreditCard className="w-5 h-5" /> },
    { path: '/transactions', label: 'Transactions', icon: <ClipboardList className="w-5 h-5" /> },
    { path: '/security', label: 'Security', icon: <Shield className="w-5 h-5" /> },
    { path: '/settings', label: 'Settings', icon: <Settings className="w-5 h-5" /> },
  ];
  
  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Desktop Sidebar */}
      <div className="hidden md:flex md:flex-shrink-0">
        <div className="flex flex-col w-64 bg-white border-r">
          <div className="flex items-center justify-center h-16 px-4 border-b">
            <h1 className="text-xl font-bold text-green-600">Secure Cipher Bank</h1>
          </div>
          <div className="flex flex-col flex-1 overflow-y-auto">
            <nav className="flex-1 px-2 py-4 space-y-1">
              {navItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center px-4 py-3 text-sm rounded-md ${
                    location.pathname === item.path
                      ? 'bg-green-100 text-green-600'
                      : 'text-gray-700 hover:bg-gray-100'
                  }`}
                >
                  {item.icon}
                  <span className="ml-3">{item.label}</span>
                </Link>
              ))}
              <hr className="my-2 border-gray-200" />
              <button className="flex items-center w-full px-4 py-3 text-sm text-gray-700 rounded-md hover:bg-gray-100">
                <LogOut className="w-5 h-5" />
                <span className="ml-3">Sign Out</span>
              </button>
            </nav>
          </div>
        </div>
      </div>
      
      {/* Mobile Header & Content */}
      <div className="flex flex-col flex-1 w-0 overflow-hidden">
        <div className="relative z-10 flex items-center justify-between h-16 flex-shrink-0 bg-white border-b md:hidden">
          <div className="flex items-center px-4">
            <h1 className="text-lg font-bold text-green-600">Secure Cipher Bank</h1>
          </div>
          <button
            className="p-4 text-gray-600 focus:outline-none focus:ring-1 focus:ring-green-500"
            onClick={toggleMobileMenu}
          >
            {isMobileMenuOpen ? (
              <X className="w-6 h-6" />
            ) : (
              <Menu className="w-6 h-6" />
            )}
          </button>
        </div>

        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="fixed inset-0 z-40 flex md:hidden">
            <div 
              className="fixed inset-0 bg-gray-600 bg-opacity-75" 
              onClick={toggleMobileMenu}
            ></div>
            <div className="relative flex flex-col flex-1 w-full max-w-xs bg-white">
              <div className="absolute top-0 right-0 pt-2">
                <button
                  className="ml-1 flex items-center justify-center h-10 w-10 rounded-full focus:outline-none"
                  onClick={toggleMobileMenu}
                >
                  <X className="w-6 h-6 text-gray-600" />
                </button>
              </div>
              <div className="flex-1 h-0 pt-5 pb-4 overflow-y-auto">
                <div className="flex items-center justify-center px-4">
                  <h1 className="text-xl font-bold text-green-600">Secure Cipher Bank</h1>
                </div>
                <nav className="mt-5 px-2 space-y-1">
                  {navItems.map((item) => (
                    <Link
                      key={item.path}
                      to={item.path}
                      className={`flex items-center px-4 py-3 text-sm rounded-md ${
                        location.pathname === item.path
                          ? 'bg-green-100 text-green-600'
                          : 'text-gray-700 hover:bg-gray-100'
                      }`}
                      onClick={toggleMobileMenu}
                    >
                      {item.icon}
                      <span className="ml-3">{item.label}</span>
                    </Link>
                  ))}
                  <hr className="my-2 border-gray-200" />
                  <button className="flex items-center w-full px-4 py-3 text-sm text-gray-700 rounded-md hover:bg-gray-100">
                    <LogOut className="w-5 h-5" />
                    <span className="ml-3">Sign Out</span>
                  </button>
                </nav>
              </div>
            </div>
          </div>
        )}

        {/* Main Content */}
        <main className="relative flex-1 overflow-y-auto focus:outline-none">
          <div className="py-6">
            <div className="px-4 mx-auto max-w-7xl sm:px-6 md:px-8">
              {children}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
