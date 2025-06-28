// AuthContext.js
import { createContext, useState, useContext, useEffect } from 'react';
import api from '../services/api';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    // Check if user is authenticated
    const checkAuth = async () => {
      try {
        const token = localStorage.getItem('authToken');
        if (token) {
          // Get user profile from API
          const profileData = await api.profile.getProfile();
          if (profileData && profileData.length > 0) {
            setProfile(profileData[0]);
            setUser(profileData[0].user);
          }
        }
      } catch (error) {
        console.error('Authentication error:', error);
        // Clear any invalid tokens
        localStorage.removeItem('authToken');
      } finally {
        setLoading(false);
      }
    };
    
    checkAuth();
  }, []);
  
  const register = async (userData) => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.auth.register(userData);
      
      // Store token
      localStorage.setItem('authToken', response.token);
      
      // Set user and profile
      setUser(response.user);
      setProfile(response.profile);
      
      return response;
    } catch (error) {
      setError(error.data || { error: 'Registration failed' });
      throw error;
    } finally {
      setLoading(false);
    }
  };
  
  const login = async (username, password) => {
    setLoading(true);
    setError(null);
    try {
      // Skip the API accessibility check for now as it's causing issues
      // Just proceed with the login directly
      
      const response = await api.auth.login(username, password);
      
      // Store token
      localStorage.setItem('authToken', response.token);
      
      // Set user and profile
      setUser(response.user);
      setProfile(response.profile);
      
      return response;
    } catch (error) {
      console.error('Login error:', error);
      
      // Handle CORS errors specifically
      if (error.message && error.message.includes('CORS')) {
        setError({ error: 'Cross-Origin Resource Sharing (CORS) error. Please try again or contact support.' });
      } else {
        setError(error.data || { error: 'Login failed' });
      }
      
      throw error;
    } finally {
      setLoading(false);
    }
  };
  
  const logout = async () => {
    setLoading(true);
    try {
      // Call logout API
      await api.auth.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear local state and storage
      setUser(null);
      setProfile(null);
      localStorage.removeItem('authToken');
      setLoading(false);
    }
  };
  
  const updatePublicKey = async (publicKey) => {
    try {
      const response = await api.auth.updatePublicKey(publicKey);
      setProfile(response.profile);
      return response;
    } catch (error) {
      console.error('Update public key error:', error);
      throw error;
    }
  };
  
  const setPin = async () => {
    try {
      const response = await api.auth.setPin();
      setProfile(response.profile);
      return response;
    } catch (error) {
      console.error('Set PIN error:', error);
      throw error;
    }
  };
  
  const updateProfile = async (profileId, profileData) => {
    try {
      const response = await api.profile.updateProfile(profileId, profileData);
      setProfile(response);
      return response;
    } catch (error) {
      console.error('Update profile error:', error);
      throw error;
    }
  };
  
  const value = {
    user,
    profile,
    loading,
    error,
    register,
    login,
    logout,
    updatePublicKey,
    setPin,
    updateProfile,
    isAuthenticated: !!user
  };
  
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
