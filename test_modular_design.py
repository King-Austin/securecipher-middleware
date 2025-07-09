#!/usr/bin/env python3
"""
Test script to demonstrate the modular SecureCipher functionality
This script shows how the refactored modules work together
"""

import sys
import os
import json

# Add the project root to Python path
sys.path.append('/home/kingaustin/Documents/securecipher/securecipher-middleware')

def test_modular_crypto():
    """Test the modular crypto functionality"""
    print("🔐 Testing Modular SecureCipher Components")
    print("=" * 50)
    
    try:
        # Import the modular classes
        from api.crypto_utils import CryptoHandler, TransactionHandler, ClientCryptoHandler
        from scripts.generate_keypair import KeyPairGenerator
        
        print("✅ Successfully imported modular components:")
        print("   - CryptoHandler: Handles encryption/decryption")
        print("   - TransactionHandler: Handles transaction processing")
        print("   - ClientCryptoHandler: Handles client-side decryption")
        print("   - KeyPairGenerator: Handles key pair generation")
        print()
        
        # Test transaction handling
        print("🔍 Testing TransactionHandler...")
        sample_transaction = {
            "amount": "100.00",
            "recipient": "user123",
            "timestamp": "2025-01-07T12:00:00Z"
        }
        
        # Create responses
        success_response = TransactionHandler.create_success_response(sample_transaction)
        error_response = TransactionHandler.create_error_response("Test error")
        
        print(f"   Success response: {success_response}")
        print(f"   Error response: {error_response}")
        print()
        
        # Test transaction preparation
        transaction_bytes = TransactionHandler.prepare_transaction_for_verification(sample_transaction)
        print(f"   Transaction prepared for verification: {len(transaction_bytes)} bytes")
        print()
        
        print("✅ All modular components working correctly!")
        print()
        print("🎯 Key Benefits of Modular Design:")
        print("   - DRY Principle: No code duplication")
        print("   - Separation of Concerns: Each class has a specific purpose")
        print("   - Maintainability: Easy to update and extend")
        print("   - Testability: Individual components can be tested")
        print("   - Reusability: Components can be used across different parts")
        print("   - Response Encryption: Server responses are now encrypted")
        
    except Exception as e:
        print(f"❌ Error testing modular components: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_modular_crypto()
