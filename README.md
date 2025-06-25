# Secure Cipher Bank

A modern, secure digital banking web application for the Nigerian market, built on the base44 platform. This application uses client-side cryptography to ensure user private keys never leave their device.

## Key Features

- **Secure User Onboarding:** Multi-step registration process with identity verification and cryptographic key pair setup
- **Transaction Security:** PIN-based authorization for all transactions with client-side signing
- **Modern UI:** Clean, responsive interface built with Tailwind CSS
- **Security Center:** Transparent security information and educational content for users

## Security Architecture

The application implements a robust security model:

1. **Key Generation:** During registration, ECDSA key pair (curve P-384) is generated using the Web Crypto API
2. **PIN Encryption:** User's 6-digit PIN is used to encrypt their private key using PBKDF2 and AES-GCM
3. **Secure Storage:** Encrypted private key is stored in IndexedDB, never in localStorage
4. **Transaction Signing:** Transactions are signed on-device after PIN verification

## Technical Stack

- **Frontend:** React, React Router, Tailwind CSS
- **UI Components:** Custom components with Tailwind styling
- **Icons:** lucide-react
- **Cryptography:** Web Crypto API (native browser)
- **Storage:** IndexedDB for secure client-side storage

## Getting Started

1. Install dependencies:
   ```
   npm install
   ```

2. Start the development server:
   ```
   npm start
   ```

3. Build for production:
   ```
   npm run build
   ```

## Project Structure

- `/src/components`: Reusable UI components
- `/src/pages`: Full page components
- `/src/utils`: Utility functions, including SecureKeyManager
- `/src/context`: React context providers
- `/src/schemas`: JSON schema definitions for data models

## License

This project is proprietary and confidential.

## Security Notice

This application implements client-side cryptography as a security measure. The private key never leaves the user's device and is encrypted with their PIN. Always ensure you're using the application on a secure device and never share your PIN with anyone.b Codespaces ♥️ React

Welcome to your shiny new Codespace running React! We've got everything fired up and running for you to explore React.

You've got a blank canvas to work on from a git perspective as well. There's a single initial commit with the what you're seeing right now - where you go from here is up to you!

Everything you do here is contained within this one codespace. There is no repository on GitHub yet. If and when you’re ready you can click "Publish Branch" and we’ll create your repository and push up your project. If you were just exploring then and have no further need for this code then you can simply delete your codespace and it's gone forever.

This project was bootstrapped for you with [Vite](https://vitejs.dev/).

## Available Scripts

In the project directory, you can run:

### `npm start`

We've already run this for you in the `Codespaces: server` terminal window below. If you need to stop the server for any reason you can just run `npm start` again to bring it back online.

Runs the app in the development mode.\
Open [http://localhost:3000/](http://localhost:3000/) in the built-in Simple Browser (`Cmd/Ctrl + Shift + P > Simple Browser: Show`) to view your running application.

The page will reload automatically when you make changes.\
You may also see any lint errors in the console.

### `npm test`

Launches the test runner in the interactive watch mode.\
See the section about [running tests](https://facebook.github.io/create-react-app/docs/running-tests) for more information.

### `npm run build`

Builds the app for production to the `build` folder.\
It correctly bundles React in production mode and optimizes the build for the best performance.

The build is minified and the filenames include the hashes.\
Your app is ready to be deployed!

See the section about [deployment](https://facebook.github.io/create-react-app/docs/deployment) for more information.

## Learn More

You can learn more in the [Vite documentation](https://vitejs.dev/guide/).

To learn Vitest, a Vite-native testing framework, go to [Vitest documentation](https://vitest.dev/guide/)

To learn React, check out the [React documentation](https://reactjs.org/).

### Code Splitting

This section has moved here: [https://sambitsahoo.com/blog/vite-code-splitting-that-works.html](https://sambitsahoo.com/blog/vite-code-splitting-that-works.html)

### Analyzing the Bundle Size

This section has moved here: [https://github.com/btd/rollup-plugin-visualizer#rollup-plugin-visualizer](https://github.com/btd/rollup-plugin-visualizer#rollup-plugin-visualizer)

### Making a Progressive Web App

This section has moved here: [https://dev.to/hamdankhan364/simplifying-progressive-web-app-pwa-development-with-vite-a-beginners-guide-38cf](https://dev.to/hamdankhan364/simplifying-progressive-web-app-pwa-development-with-vite-a-beginners-guide-38cf)

### Advanced Configuration

This section has moved here: [https://vitejs.dev/guide/build.html#advanced-base-options](https://vitejs.dev/guide/build.html#advanced-base-options)

### Deployment

This section has moved here: [https://vitejs.dev/guide/build.html](https://vitejs.dev/guide/build.html)

### Troubleshooting

This section has moved here: [https://vitejs.dev/guide/troubleshooting.html](https://vitejs.dev/guide/troubleshooting.html)
