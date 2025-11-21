import React from 'react';

// Simple Dialog component implementation
export const Dialog = ({ open, onOpenChange, children }) => {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div 
        className="fixed inset-0 bg-black bg-opacity-50"
        onClick={() => onOpenChange(false)}
      />
      <div className="relative bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-4xl w-full mx-4">
        {children}
      </div>
    </div>
  );
};

export const DialogContent = ({ children, className = "" }) => (
  <div className={`p-6 ${className}`}>
    {children}
  </div>
);

export const DialogHeader = ({ children }) => (
  <div className="mb-4 pb-4 border-b border-gray-200 dark:border-gray-700">
    {children}
  </div>
);

export const DialogTitle = ({ children, className = "" }) => (
  <h2 className={`text-xl font-semibold text-gray-900 dark:text-white ${className}`}>
    {children}
  </h2>
);

export const DialogDescription = ({ children, className = "" }) => (
  <p className={`text-sm text-gray-600 dark:text-gray-400 mt-1 ${className}`}>
    {children}
  </p>
);

// Simple Tabs component implementation
export const Tabs = ({ value, onValueChange, children, className = "" }) => (
  <div className={className} data-active-tab={value}>
    {React.Children.map(children, child =>
      React.cloneElement(child, { activeTab: value, onTabChange: onValueChange })
    )}
  </div>
);

export const TabsList = ({ children, className = "", activeTab, onTabChange }) => (
  <div className={`flex space-x-1 bg-gray-100 dark:bg-gray-700 p-1 rounded-lg ${className}`}>
    {React.Children.map(children, child =>
      React.cloneElement(child, { activeTab, onTabChange })
    )}
  </div>
);

export const TabsTrigger = ({ value, children, activeTab, onTabChange, className = "" }) => (
  <button
    onClick={() => onTabChange(value)}
    className={`px-3 py-2 text-sm font-medium rounded-md transition-colors ${
      activeTab === value
        ? 'bg-white dark:bg-gray-600 text-blue-600 dark:text-blue-400 shadow'
        : 'text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white'
    } ${className}`}
  >
    {children}
  </button>
);

export const TabsContent = ({ value, children, activeTab, className = "" }) => {
  if (activeTab !== value) return null;
  return <div className={className}>{children}</div>;
};

// Simple Badge component
export const Badge = ({ children, variant = "default", className = "" }) => {
  const variants = {
    default: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
    success: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
    destructive: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
    warning: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
    outline: "border border-gray-300 text-gray-700 dark:border-gray-600 dark:text-gray-300",
    secondary: "bg-gray-200 text-gray-800 dark:bg-gray-600 dark:text-gray-200"
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${variants[variant]} ${className}`}>
      {children}
    </span>
  );
};

// Simple Card components
export const Card = ({ children, className = "" }) => (
  <div className={`bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow ${className}`}>
    {children}
  </div>
);

export const CardHeader = ({ children, className = "" }) => (
  <div className={`p-6 pb-4 ${className}`}>
    {children}
  </div>
);

export const CardTitle = ({ children, className = "" }) => (
  <h3 className={`text-lg font-semibold text-gray-900 dark:text-white ${className}`}>
    {children}
  </h3>
);

export const CardDescription = ({ children, className = "" }) => (
  <p className={`text-sm text-gray-600 dark:text-gray-400 mt-1 ${className}`}>
    {children}
  </p>
);

export const CardContent = ({ children, className = "" }) => (
  <div className={`p-6 pt-0 ${className}`}>
    {children}
  </div>
);
