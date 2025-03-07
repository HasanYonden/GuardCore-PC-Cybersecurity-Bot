import React, { createContext, useContext, useState, useEffect } from 'react';

// Create context
const UserLevelContext = createContext();

// Custom hook to use the user level context
export const useUserLevel = () => {
  const context = useContext(UserLevelContext);
  if (!context) {
    throw new Error('useUserLevel must be used within a UserLevelProvider');
  }
  return context;
};

// Provider component
export const UserLevelProvider = ({ children }) => {
  // Available user levels
  const levels = {
    beginner: {
      name: 'Beginner',
      description: 'Simplified view with essential features and guided help',
      features: ['basic_protections', 'guided_scans', 'simplified_settings']
    },
    intermediate: {
      name: 'Intermediate',
      description: 'More detailed information and additional control options',
      features: ['basic_protections', 'guided_scans', 'simplified_settings', 'advanced_scans', 'detailed_reports', 'custom_rules']
    },
    advanced: {
      name: 'Advanced',
      description: 'Full access to all features and technical details',
      features: ['basic_protections', 'guided_scans', 'simplified_settings', 'advanced_scans', 'detailed_reports', 'custom_rules', 'expert_settings', 'command_line', 'api_access']
    }
  };

  // Get initial level from local storage or default to beginner
  const getInitialLevel = () => {
    const savedLevel = localStorage.getItem('guardcore-user-level');
    return levels[savedLevel] ? savedLevel : 'beginner';
  };

  const [userLevel, setUserLevel] = useState(getInitialLevel);
  
  // Store user level preference when it changes
  useEffect(() => {
    localStorage.setItem('guardcore-user-level', userLevel);
  }, [userLevel]);
  
  // Set a specific user level
  const setLevel = (level) => {
    if (levels[level]) {
      setUserLevel(level);
    }
  };
  
  // Check if a specific feature is available at current level
  const hasFeature = (featureName) => {
    return levels[userLevel].features.includes(featureName);
  };
  
  // Get all available levels
  const getLevels = () => {
    return Object.entries(levels).map(([key, value]) => ({
      id: key,
      ...value
    }));
  };
  
  // Get current level details
  const getCurrentLevel = () => {
    return {
      id: userLevel,
      ...levels[userLevel]
    };
  };
  
  // Value object to be provided by context
  const value = {
    userLevel,
    setUserLevel: setLevel,
    hasFeature,
    levels: getLevels(),
    currentLevel: getCurrentLevel()
  };
  
  return (
    <UserLevelContext.Provider value={value}>
      {children}
    </UserLevelContext.Provider>
  );
};