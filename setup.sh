#!/bin/bash

# SecureCipher Middleware Setup Script
# This script sets up the development environment and runs initial migrations

echo "🔐 Setting up SecureCipher Middleware..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Copy environment file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️ Creating environment file..."
    cp .env.example .env
    echo "⚠️ Please update .env with your actual configuration values!"
fi

# Create logs directory
echo "📝 Creating logs directory..."
mkdir -p logs

# Run Django migrations
echo "🗄️ Running database migrations..."
python manage.py makemigrations crypto_engine
python manage.py migrate

# Create superuser if needed
echo "👤 Creating superuser account..."
echo "You can skip this if you already have a superuser account."
python manage.py createsuperuser --noinput --username admin --email admin@securecipher.local || echo "Superuser already exists or skipped"

# Collect static files (for production)
echo "📁 Collecting static files..."
python manage.py collectstatic --noinput || echo "Static files collection skipped"

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 To start the development server:"
echo "   source venv/bin/activate"
echo "   python manage.py runserver"
echo ""
echo "🔗 Available endpoints:"
echo "   • Health Check: http://localhost:8000/health/"
echo "   • Admin Panel: http://localhost:8000/admin/"
echo "   • Register Key: http://localhost:8000/api/auth/register-key/"
echo "   • Verify Signature: http://localhost:8000/api/auth/verify-signature/"
echo "   • Crypto Status: http://localhost:8000/api/auth/crypto-status/"
echo ""
echo "📋 Next steps:"
echo "   1. Update .env with your configuration"
echo "   2. Start the frontend application"
echo "   3. Test crypto key registration from frontend"
echo ""
