"use client";

import { useState } from "react";
import Dashboard from "../components/Dashboard";

export default function Home() {
  return (
    <main className="container mx-auto px-4 py-8">
      <div className="text-center mb-8">
        <h1 className="text-4xl font-bold text-gray-900 mb-2">SENTINEL</h1>
        <p className="text-xl text-gray-600">
          AI-Powered Isolated Security Testing Platform
        </p>
      </div>
      <Dashboard />
    </main>
  );
}
