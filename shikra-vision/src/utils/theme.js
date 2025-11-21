// Theme utilities for light, dark, and system theme support
export const THEME_MODES = {
  LIGHT: 'light',
  DARK: 'dark',
  SYSTEM: 'system'
};

// Initialize theme on page load
export const initializeTheme = () => {
  // This should be called inline in head to avoid FOUC
  const script = `
    (function() {
      const theme = localStorage.getItem('theme');
      const isDark = theme === 'dark' || 
        (!theme && window.matchMedia('(prefers-color-scheme: dark)').matches);
      
      if (isDark) {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
    })();
  `;
  return script;
};

// Apply theme based on preference
export const applyTheme = (theme) => {
  const root = document.documentElement;
  
  switch (theme) {
    case THEME_MODES.LIGHT:
      localStorage.theme = 'light';
      root.classList.remove('dark');
      break;
      
    case THEME_MODES.DARK:
      localStorage.theme = 'dark';
      root.classList.add('dark');
      break;
      
    case THEME_MODES.SYSTEM:
      localStorage.removeItem('theme');
      const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      if (isDark) {
        root.classList.add('dark');
      } else {
        root.classList.remove('dark');
      }
      break;
      
    default:
      break;
  }
};

// Get current theme
export const getCurrentTheme = () => {
  const stored = localStorage.getItem('theme');
  if (stored === 'light' || stored === 'dark') {
    return stored;
  }
  return THEME_MODES.SYSTEM;
};

// Check if currently in dark mode
export const isDarkMode = () => {
  return document.documentElement.classList.contains('dark');
};

// Listen for system theme changes
export const watchSystemTheme = (callback) => {
  const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
  
  const handleChange = (e) => {
    const currentTheme = getCurrentTheme();
    if (currentTheme === THEME_MODES.SYSTEM) {
      if (e.matches) {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
      callback?.(e.matches);
    }
  };
  
  mediaQuery.addEventListener('change', handleChange);
  
  // Return cleanup function
  return () => mediaQuery.removeEventListener('change', handleChange);
};

// Watch for dark class changes on html element
export const watchDarkModeChanges = (callback) => {
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
        const isDark = document.documentElement.classList.contains('dark');
        callback(isDark);
      }
    });
  });

  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['class']
  });

  // Return cleanup function
  return () => observer.disconnect();
};
