import { useState } from 'react';
import { User, Camera } from 'lucide-react';

export default function EditProfile() {
  const [formData, setFormData] = useState({
    full_name: 'Samuel Johnson',
    email: 'samuel.johnson@example.com',
    phone: '+234 812 345 6789',
    address: '23 Lagos Street, Ikeja, Lagos',
    occupation: 'Software Engineer'
  });
  
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };
  
  const handleSubmit = (e) => {
    e.preventDefault();
    // In a real app, this would update the user's profile
    console.log('Updated profile data:', formData);
    alert('Profile updated successfully!');
  };

  return (
    <div>
      <h2 className="text-lg font-medium text-gray-800 mb-4">Edit Profile</h2>
      
      <div className="flex flex-col sm:flex-row items-center mb-6">
        <div className="relative mb-4 sm:mb-0 sm:mr-6">
          <div className="h-24 w-24 rounded-full bg-gray-200 flex items-center justify-center text-gray-400">
            <User className="h-12 w-12" />
          </div>
          <button className="absolute bottom-0 right-0 bg-white rounded-full p-1.5 shadow-sm border border-gray-200">
            <Camera className="h-4 w-4 text-gray-600" />
          </button>
        </div>
        
        <div>
          <h3 className="text-md font-medium text-gray-800">{formData.full_name}</h3>
          <p className="text-sm text-gray-500">Account No: 1234567890</p>
        </div>
      </div>
      
      <form onSubmit={handleSubmit}>
        <div className="space-y-4">
          <div>
            <label htmlFor="full_name" className="block text-sm font-medium text-gray-700 mb-1">
              Full Name
            </label>
            <input
              type="text"
              id="full_name"
              name="full_name"
              value={formData.full_name}
              onChange={handleChange}
              className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
            />
          </div>
          
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
              Email Address
            </label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
            />
          </div>
          
          <div>
            <label htmlFor="phone" className="block text-sm font-medium text-gray-700 mb-1">
              Phone Number
            </label>
            <input
              type="tel"
              id="phone"
              name="phone"
              value={formData.phone}
              onChange={handleChange}
              className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
            />
          </div>
          
          <div>
            <label htmlFor="address" className="block text-sm font-medium text-gray-700 mb-1">
              Address
            </label>
            <input
              type="text"
              id="address"
              name="address"
              value={formData.address}
              onChange={handleChange}
              className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
            />
          </div>
          
          <div>
            <label htmlFor="occupation" className="block text-sm font-medium text-gray-700 mb-1">
              Occupation
            </label>
            <input
              type="text"
              id="occupation"
              name="occupation"
              value={formData.occupation}
              onChange={handleChange}
              className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm"
            />
          </div>
        </div>
        
        <div className="mt-6">
          <button
            type="submit"
            className="w-full sm:w-auto inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
          >
            Save Changes
          </button>
        </div>
      </form>
    </div>
  );
}
