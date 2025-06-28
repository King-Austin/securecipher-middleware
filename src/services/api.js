/**
 * API service for making requests to the backend
 */

// Helper to determine if we're running in GitHub Codespaces
const isGitHubCodespaces = () => {
  return window.location.hostname.includes('.github.dev');
};

// Determine the API URL based on environment
const getApiUrl = () => {
  if (process.env.NODE_ENV === 'production') {
    return "/api";
  } else if (isGitHubCodespaces()) {
    // In GitHub Codespaces, we need to point to the backend service on port 8000
    // Replace the port in the current URL
    const hostname = window.location.hostname.split('-')[0];
    return `https://${hostname}-8000.app.github.dev/api`;
  } else {
    return "http://localhost:8000/api";
  }
};

const API_URL = getApiUrl();

/**
 * Make an authenticated request to the API
 * 
 * @param {string} endpoint - The API endpoint to request
 * @param {Object} options - Request options
 * @returns {Promise<any>} - Response data
 */
const apiRequest = async (endpoint, options = {}) => {
  // Get auth token from localStorage
  const token = localStorage.getItem("authToken");
  
  // Set default headers
  const headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Origin": window.location.origin,
    ...(token && { Authorization: `Token ${token}` }),
    ...options.headers,
  };
  
  // Set credentials option to include cookies if needed
  const requestOptions = {
    ...options,
    headers,
    credentials: 'include', // This ensures cookies are sent with the request
    mode: 'cors',           // Explicitly set CORS mode
  };
  
  // Make the request
  const response = await fetch(`${API_URL}${endpoint}`, requestOptions);
  
  // Check if the response is JSON
  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    const data = await response.json();
    
    // If the response is not ok, throw an error
    if (!response.ok) {
      const error = new Error(data.error || "Something went wrong");
      error.status = response.status;
      error.data = data;
      throw error;
    }
    
    return data;
  }
  
  // If the response is not JSON, return the response
  if (!response.ok) {
    const error = new Error("Something went wrong");
    error.status = response.status;
    throw error;
  }
  
  return response;
};

/**
 * Authentication API calls
 */
export const authAPI = {
  /**
   * Register a new user
   * 
   * @param {Object} userData - User registration data
   * @returns {Promise<Object>} - User data and token
   */
  register: (userData) => {
    return apiRequest("/auth/register/", {
      method: "POST",
      body: JSON.stringify(userData),
    });
  },
  
  /**
   * Login a user
   * 
   * @param {string} username - Username
   * @param {string} password - Password
   * @returns {Promise<Object>} - User data and token
   */
  login: (username, password) => {
    // For login requests, we need to be extra careful with CORS
    return fetch(`${API_URL}/auth/login/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": window.location.origin,
      },
      body: JSON.stringify({ username, password }),
      credentials: 'include',
      mode: 'cors',
    }).then(response => {
      if (response.ok) {
        return response.json();
      }
      
      if (response.headers.get("content-type")?.includes("application/json")) {
        return response.json().then(data => {
          const error = new Error(data.error || "Login failed");
          error.status = response.status;
          error.data = data;
          throw error;
        });
      }
      
      const error = new Error("Login failed");
      error.status = response.status;
      throw error;
    });
  },
  
  /**
   * Logout the current user
   * 
   * @returns {Promise<void>}
   */
  logout: () => {
    return apiRequest("/auth/logout/", {
      method: "POST",
    });
  },
  
  /**
   * Update the user's public key
   * 
   * @param {string} publicKey - The user's public key
   * @returns {Promise<Object>} - Updated profile data
   */
  updatePublicKey: (publicKey) => {
    return apiRequest("/auth/update-public-key/", {
      method: "POST",
      body: JSON.stringify({ public_key: publicKey }),
    });
  },
  
  /**
   * Mark that the user has set their PIN
   * 
   * @returns {Promise<Object>} - Updated profile data
   */
  setPin: () => {
    return apiRequest("/auth/set-pin/", {
      method: "POST",
    });
  },
};

/**
 * User profile API calls
 */
export const profileAPI = {
  /**
   * Get the current user's profile
   * 
   * @returns {Promise<Object>} - User profile data
   */
  getProfile: () => {
    return apiRequest("/profiles/");
  },
  
  /**
   * Update the current user's profile
   * 
   * @param {string} profileId - Profile ID
   * @param {Object} profileData - Updated profile data
   * @returns {Promise<Object>} - Updated profile data
   */
  updateProfile: (profileId, profileData) => {
    return apiRequest(`/profiles/${profileId}/`, {
      method: "PUT",
      body: JSON.stringify(profileData),
    });
  },
};

/**
 * Transaction API calls
 */
export const transactionAPI = {
  /**
   * Get all transactions for the current user
   * 
   * @returns {Promise<Array>} - List of transactions
   */
  getTransactions: () => {
    return apiRequest("/transactions/");
  },
  
  /**
   * Get a specific transaction
   * 
   * @param {string} transactionId - Transaction ID
   * @returns {Promise<Object>} - Transaction data
   */
  getTransaction: (transactionId) => {
    return apiRequest(`/transactions/${transactionId}/`);
  },
  
  /**
   * Verify an account number
   * 
   * @param {string} accountNumber - Account number to verify
   * @returns {Promise<Object>} - Account verification data
   */
  verifyAccount: (accountNumber) => {
    return apiRequest(`/transactions/verify-account/${accountNumber}/`);
  },
  
  /**
   * Create a new transfer
   * 
   * @param {Object} transferData - Transfer data
   * @returns {Promise<Object>} - Created transaction data
   */
  createTransfer: (transferData) => {
    return apiRequest("/transactions/transfer/", {
      method: "POST",
      body: JSON.stringify(transferData),
    });
  },
};

/**
 * Card API calls
 */
export const cardAPI = {
  /**
   * Get all cards for the current user
   * 
   * @returns {Promise<Array>} - List of cards
   */
  getCards: () => {
    return apiRequest("/cards/");
  },
  
  /**
   * Get a specific card
   * 
   * @param {string} cardId - Card ID
   * @returns {Promise<Object>} - Card data
   */
  getCard: (cardId) => {
    return apiRequest(`/cards/${cardId}/`);
  },
  
  /**
   * Create a new card
   * 
   * @param {Object} cardData - Card data
   * @returns {Promise<Object>} - Created card data
   */
  createCard: (cardData) => {
    return apiRequest("/cards/", {
      method: "POST",
      body: JSON.stringify(cardData),
    });
  },
  
  /**
   * Update a card
   * 
   * @param {string} cardId - Card ID
   * @param {Object} cardData - Updated card data
   * @returns {Promise<Object>} - Updated card data
   */
  updateCard: (cardId, cardData) => {
    return apiRequest(`/cards/${cardId}/`, {
      method: "PUT",
      body: JSON.stringify(cardData),
    });
  },
  
  /**
   * Delete a card
   * 
   * @param {string} cardId - Card ID
   * @returns {Promise<void>}
   */
  deleteCard: (cardId) => {
    return apiRequest(`/cards/${cardId}/`, {
      method: "DELETE",
    });
  },
};

/**
 * Message API calls
 */
export const messageAPI = {
  /**
   * Get all messages for the current user
   * 
   * @returns {Promise<Array>} - List of messages
   */
  getMessages: () => {
    return apiRequest("/messages/");
  },
  
  /**
   * Get a specific message
   * 
   * @param {string} messageId - Message ID
   * @returns {Promise<Object>} - Message data
   */
  getMessage: (messageId) => {
    return apiRequest(`/messages/${messageId}/`);
  },
  
  /**
   * Mark a message as read
   * 
   * @param {string} messageId - Message ID
   * @returns {Promise<Object>} - Updated message data
   */
  markAsRead: (messageId) => {
    return apiRequest(`/messages/${messageId}/read/`, {
      method: "POST",
    });
  },
};

// Helper function to check if the API is accessible
export const checkApiAccessibility = async () => {
  try {
    const response = await fetch(`${API_URL}`, {
      method: 'OPTIONS',
      headers: {
        'Accept': 'application/json',
        'Origin': window.location.origin,
      },
      mode: 'cors',
      credentials: 'include',
    });
    
    return response.ok;
  } catch (error) {
    console.error('API accessibility check failed:', error);
    return false;
  }
};

// Export all APIs as a default object
const api = {
  auth: authAPI,
  profile: profileAPI,
  transaction: transactionAPI,
  card: cardAPI,
  message: messageAPI,
};

export default api;
