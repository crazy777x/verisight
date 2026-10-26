'use client';

import React, { useState } from 'react';
import { Button } from '@/components/ui/button';

export function LoginGateway() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleFillDemo = () => {
    setEmail('admin@verisight.local');
    setPassword('admin123');
  };

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 px-4">
      <div className="w-full max-w-md space-y-6 rounded-xl border border-gray-800 bg-gray-900 p-8 shadow-2xl">
        
        <div className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-4 text-sm text-blue-200">
          <p className="font-semibold mb-1 flex items-center gap-2">
            <span>🛡️</span> Judge Demo Access:
          </p>
          <p className="text-xs text-blue-300/80 mb-3">
            Email: <code className="bg-black/30 px-1 py-0.5 rounded text-blue-100">admin@verisight.local</code><br />
            Password: <code className="bg-black/30 px-1 py-0.5 rounded text-blue-100">admin123</code>
          </p>
          <Button 
            type="button" 
            variant="outline" 
            size="sm" 
            onClick={handleFillDemo}
            className="w-full border-blue-500/50 text-blue-200 hover:bg-blue-500/20 text-xs py-1"
          >
            ⚡ Fill Demo Credentials
          </Button>
        </div>

        <div className="text-center">
          <h1 className="text-2xl font-bold tracking-tight text-white">VeriSight Gateway</h1>
          <p className="text-sm text-gray-400 mt-1">Enterprise Document Verification System</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">Email ID</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full rounded-md border border-gray-800 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              placeholder="Enter email..."
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full rounded-md border border-gray-800 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              placeholder="Enter password..."
            />
          </div>

          <Button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2">
            Secure Login
          </Button>
        </form>
      </div>
    </div>
  );
}