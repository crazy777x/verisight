// components/ForensicScannerLoader.tsx
'use client';
import { useState, useEffect } from 'react';

const verificationSteps = [
  "Initializing VeriSight Secure Enclave...",
  "Extracting PDF Metadata & Digital Signature...",
  "Cross-matching Secure QR with Printed OCR...",
  "Verifying Cryptographic Certificate Chain...",
  "Running Zero-Knowledge Tamper Diagnostics..."
];

export default function ForensicScannerLoader() {
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentStep((prev) => (prev < verificationSteps.length - 1 ? prev + 1 : prev));
    }, 800);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative flex flex-col items-center justify-center p-12 bg-slate-950 border border-cyan-500/30 rounded-2xl shadow-2xl overflow-hidden min-h-[350px] w-full">
      {/* Background Grid Lines */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#082f49_1px,transparent_1px),linear-gradient(to_bottom,#082f49_1px,transparent_1px)] bg-[size:2rem_2rem] opacity-20 animate-pulse"></div>

      {/* Magnifying Glass / Scanner Box */}
      <div className="relative w-48 h-48 border-2 border-cyan-400 rounded-lg flex items-center justify-center shadow-[0_0_30px_rgba(6,182,212,0.3)] bg-cyan-950/20 backdrop-blur-sm mb-6">
        
        {/* Moving Laser Scan Line */}
        <div className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-bounce shadow-[0_0_15px_#22d3ee]"></div>

        {/* Magnifying Glass Icon / Reticle */}
        <div className="relative flex items-center justify-center">
          <svg className="w-16 h-16 text-cyan-400 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <div className="absolute w-2 h-2 bg-cyan-400 rounded-full animate-ping"></div>
        </div>

        {/* Corner Borders */}
        <div className="absolute top-0 left-0 w-3 h-3 border-t-2 border-l-2 border-cyan-300"></div>
        <div className="absolute top-0 right-0 w-3 h-3 border-t-2 border-r-2 border-cyan-300"></div>
        <div className="absolute bottom-0 left-0 w-3 h-3 border-b-2 border-l-2 border-cyan-300"></div>
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b-2 border-r-2 border-cyan-300"></div>
      </div>

      {/* Dynamic Status Text */}
      <div className="text-center z-10">
        <p className="text-cyan-300 font-mono text-sm tracking-wider uppercase mb-2 animate-pulse">
          [ Forensic Triage in Progress ]
        </p>
        <h3 className="text-white font-semibold text-lg transition-all duration-300">
          {verificationSteps[currentStep]}
        </h3>
      </div>

      {/* Progress Dots */}
      <div className="flex gap-2 mt-6 z-10">
        {verificationSteps.map((_, idx) => (
          <div
            key={idx}
            className={`h-1.5 rounded-full transition-all duration-500 ${
              idx <= currentStep ? 'w-8 bg-cyan-400 shadow-[0_0_10px_#22d3ee]' : 'w-2 bg-slate-800'
            }`}
          />
        ))}
      </div>
    </div>
  );
}