import React, { useMemo, useState } from 'react';

interface Props {
  children: React.ReactNode;
}

const SESSION_KEY = 'signature_web_verifier_access';

export const VerifierAccessGate: React.FC<Props> = ({ children }) => {
  const gateEnabled = import.meta.env.VITE_VERIFIER_LOGIN_REQUIRED === 'false';

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isAllowed, setIsAllowed] = useState(() => {
    if (!gateEnabled) return true;
    return sessionStorage.getItem(SESSION_KEY) === 'ok';
  });

  const helperText = useMemo(() => {
    if (gateEnabled) return 'Enter the verifier credentials for this browser session.';
    return 'Verifier access is open because no verifier credentials are configured.';
  }, [gateEnabled]);

  if (isAllowed) {
    return <>{children}</>;
  }

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      const response = await fetch('/.netlify/functions/verifier-login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (response.ok) {
        sessionStorage.setItem(SESSION_KEY, 'ok');
        setIsAllowed(true);
        return;
      }

      setError(response.status === 503
        ? 'Verifier access is not configured on this site.'
        : 'The verifier username or password is incorrect.');
    } catch {
      setError('Could not reach the verifier login service.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 text-gray-800 font-sans p-4 sm:p-6 lg:p-8">
      <div className="max-w-xl mx-auto mt-16 bg-white rounded-lg shadow-md p-6 border border-gray-200">
        <h1 className="text-3xl font-bold text-gray-900">SLH-DSA Test Bed</h1>
        <h2 className="mt-6 text-2xl font-semibold text-gray-800">Verifier Access</h2>
        <p className="mt-1 text-sm text-gray-600">{helperText}</p>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <label htmlFor="verifier-username" className="block text-sm font-medium text-gray-700 mb-1">
              Username
            </label>
            <input
              id="verifier-username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(event) => {
                setUsername(event.target.value);
                setError(null);
              }}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition"
            />
          </div>

          <div>
            <label htmlFor="verifier-password" className="block text-sm font-medium text-gray-700 mb-1">
              Password
            </label>
            <input
              id="verifier-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                setError(null);
              }}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition"
            />
          </div>

          {error && <p className="text-sm text-red-600">{error}</p>}

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-2 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
          >
            {isSubmitting ? 'Checking...' : 'Continue'}
          </button>
        </form>
      </div>
    </div>
  );
};
