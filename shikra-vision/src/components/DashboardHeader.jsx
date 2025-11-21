import React from 'react';
import useCyberStore from '../store/cyberStore';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  Cog6ToothIcon,
  BellIcon
} from '@heroicons/react/24/outline';

const DashboardHeader = () => {
  const { 
    searchQuery, 
    setSearchQuery, 
    darkMode, 
    setDarkMode,
    metrics 
  } = useCyberStore();

  return (
    <header className="bg-white shadow-sm border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-6">
          {/* Logo and Title */}
          <div className="flex items-center">
            <div className="flex items-center">
              <ShieldCheckIcon className="h-8 w-8 text-blue-600" />
              <h1 className="ml-3 text-2xl font-bold text-gray-900">
                SHIKRA VISION
              </h1>
            </div>
            
            {/* Status Indicator */}
            <div className="ml-6 flex items-center">
              <div className="flex items-center">
                <div className="h-2 w-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="ml-2 text-sm text-gray-600">Live Monitoring</span>
              </div>
            </div>
          </div>

          {/* Search and Controls */}
          <div className="flex items-center space-x-4">
            {/* Search Bar */}
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="text"
                className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Search IOCs, processes, IPs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            {/* Alerts Indicator */}
            <div className="relative">
              <button className="p-2 text-gray-400 hover:text-gray-500 relative">
                <BellIcon className="h-6 w-6" />
                {metrics.criticalAlerts > 0 && (
                  <span className="absolute -top-1 -right-1 h-4 w-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                    {metrics.criticalAlerts}
                  </span>
                )}
              </button>
            </div>

            {/* Settings */}
            <button className="p-2 text-gray-400 hover:text-gray-500">
              <Cog6ToothIcon className="h-6 w-6" />
            </button>

            {/* Dark Mode Toggle */}
            <button
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 text-gray-400 hover:text-gray-500"
            >
              {darkMode ? '🌞' : '🌙'}
            </button>
          </div>
        </div>

        {/* Threat Level Banner */}
        {metrics.riskScore >= 8 && (
          <div className="mb-4 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded flex items-center">
            <ExclamationTriangleIcon className="h-5 w-5 mr-2" />
            <span className="font-medium">High Threat Level Detected</span>
            <span className="ml-2">- Immediate attention required</span>
          </div>
        )}
      </div>
    </header>
  );
};

export default DashboardHeader;
