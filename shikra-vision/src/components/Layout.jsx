import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import useCyberStore from '../store/cyberStore';
import { 
  ShieldCheckIcon, 
  CpuChipIcon,
  GlobeAltIcon,
  DocumentChartBarIcon,
  ClipboardDocumentListIcon,
  BellIcon,
  Cog6ToothIcon,
  Bars3Icon,
  XMarkIcon
} from '@heroicons/react/24/outline';

const Layout = ({ children }) => {
  const location = useLocation();
  const { 
    sidebarOpen, 
    setSidebarOpen,
    metrics,
    searchQuery,
    setSearchQuery
  } = useCyberStore();

  const navigation = [
    { name: 'Overview', href: '/', icon: DocumentChartBarIcon },
    { name: 'Memory Analysis', href: '/memory', icon: CpuChipIcon },
    { name: 'Network Analysis', href: '/network', icon: GlobeAltIcon },
    { name: 'Process Monitor', href: '/procmon', icon: ClipboardDocumentListIcon },
    { name: 'Combined Report', href: '/combined', icon: ShieldCheckIcon },
  ];

  const isActive = (href) => {
    if (href === '/') return location.pathname === '/';
    return location.pathname.startsWith(href);
  };

  return (
    <div className="min-h-screen flex bg-gray-50 dark:bg-gray-900">
      {/* Sidebar */}
      <div className={`fixed inset-y-0 left-0 z-50 w-64 bg-white dark:bg-gray-800 transform ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      } transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0 lg:flex lg:flex-col`}>
        <div className="flex items-center justify-between h-16 px-6 border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
          <div className="flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-blue-600 dark:text-blue-400" />
            <span className="ml-2 text-xl font-bold text-gray-900 dark:text-white">SHIKRA VISION</span>
          </div>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700"
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>

        <nav className=" mt-5 px-3 pb-4 overflow-y-auto">
          <div className="space-y-1">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`${
                    isActive(item.href)
                      ? 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-200'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                  } group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors`}
                >
                  <Icon 
                    className={`${
                      isActive(item.href) 
                        ? 'text-blue-500 dark:text-blue-400' 
                        : 'text-gray-400 group-hover:text-gray-500 dark:group-hover:text-gray-300'
                    } mr-3 h-6 w-6 transition-colors`} 
                  />
                  {item.name}
                </Link>
              );
            })}
          </div>
        </nav>

        {/* Threat Level Indicator */}
        <div className="p-4 flex-shrink-0">
          <div className={`p-3 rounded-lg ${
            metrics.riskScore >= 8 ? 'bg-red-100 dark:bg-red-900' :
            metrics.riskScore >= 6 ? 'bg-orange-100 dark:bg-orange-900' :
            metrics.riskScore >= 4 ? 'bg-yellow-100 dark:bg-yellow-900' :
            'bg-green-100 dark:bg-green-900'
          }`}>
            <div className="flex items-center justify-between">
              <span className={`text-sm font-medium ${
                metrics.riskScore >= 8 ? 'text-red-800 dark:text-red-200' :
                metrics.riskScore >= 6 ? 'text-orange-800 dark:text-orange-200' :
                metrics.riskScore >= 4 ? 'text-yellow-800 dark:text-yellow-200' :
                'text-green-800 dark:text-green-200'
              }`}>
                Risk Level
              </span>
              <span className={`text-lg font-bold ${
                metrics.riskScore >= 8 ? 'text-red-900 dark:text-red-100' :
                metrics.riskScore >= 6 ? 'text-orange-900 dark:text-orange-100' :
                metrics.riskScore >= 4 ? 'text-yellow-900 dark:text-yellow-100' :
                'text-green-900 dark:text-green-100'
              }`}>
                {metrics.riskScore.toFixed(1)}
              </span>
            </div>
            <div className={`mt-1 w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2`}>
              <div 
                className={`h-2 rounded-full transition-all duration-500 ${
                  metrics.riskScore >= 8 ? 'bg-red-600' :
                  metrics.riskScore >= 6 ? 'bg-orange-600' :
                  metrics.riskScore >= 4 ? 'bg-yellow-600' :
                  'bg-green-600'
                }`}
                style={{ width: `${(metrics.riskScore / 10) * 100}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 lg:ml-0">
        {/* Top header */}
        <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
          <div className="px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
              {/* Mobile menu button */}
              <button
                onClick={() => setSidebarOpen(true)}
                className="lg:hidden p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                <Bars3Icon className="h-6 w-6" />
              </button>

              {/* Page title */}
              <div className="flex-1 lg:flex-none">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                  {navigation.find(item => isActive(item.href))?.name || 'ThreatScope Analytics'}
                </h1>
              </div>

              {/* Search and controls */}
              <div className="flex items-center space-x-4">
                {/* Search */}
                <div className="relative hidden sm:block">
                  <input
                    type="text"
                    className="block w-64 pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md leading-5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Search IOCs, processes, IPs..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <svg className="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                  </div>
                </div>

                {/* Alerts */}
                <div className="relative">
                  <button className="p-2 text-gray-400 hover:text-gray-500 dark:text-gray-300 dark:hover:text-gray-200 relative">
                    <BellIcon className="h-6 w-6" />
                    {metrics.criticalAlerts > 0 && (
                      <span className="absolute -top-1 -right-1 h-4 w-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center animate-pulse">
                        {metrics.criticalAlerts}
                      </span>
                    )}
                  </button>
                </div>

                {/* Settings */}
                <button className="p-2 text-gray-400 hover:text-gray-500 dark:text-gray-300 dark:hover:text-gray-200">
                  <Cog6ToothIcon className="h-6 w-6" />
                </button>
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <div className="p-4 sm:p-6 lg:p-8">
            {children}
          </div>
        </main>
      </div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 lg:hidden bg-gray-600 bg-opacity-75"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
};

export default Layout;
