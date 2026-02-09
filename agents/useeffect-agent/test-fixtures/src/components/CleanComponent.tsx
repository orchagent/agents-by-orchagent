import React, { useState, useEffect, useRef, useMemo } from 'react';

interface ThemeToggleProps {
  theme: 'light' | 'dark';
  onThemeChange: (theme: 'light' | 'dark') => void;
}

/**
 * A clean component with only necessary useEffects.
 * The agent should mark this file as clean.
 */
export function ThemeToggle({ theme, onThemeChange }: ThemeToggleProps) {
  // GOOD: Derived state computed during render
  const isDark = theme === 'dark';
  const icon = isDark ? '🌙' : '☀️';

  function handleToggle() {
    // GOOD: Parent notification in event handler
    onThemeChange(isDark ? 'light' : 'dark');
  }

  // NECESSARY: Sync with external system (document body class)
  useEffect(() => {
    document.body.classList.toggle('dark-mode', isDark);
    return () => {
      document.body.classList.remove('dark-mode');
    };
  }, [isDark]);

  return (
    <button onClick={handleToggle} aria-label="Toggle theme">
      {icon}
    </button>
  );
}

interface TimerProps {
  duration: number;
  onExpire: () => void;
}

export function Timer({ duration, onExpire }: TimerProps) {
  const [remaining, setRemaining] = useState(duration);

  // NECESSARY: Interval with cleanup
  useEffect(() => {
    const interval = setInterval(() => {
      setRemaining(prev => {
        if (prev <= 1) {
          clearInterval(interval);
          onExpire();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [duration, onExpire]);

  // GOOD: Derived state
  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  const display = `${minutes}:${seconds.toString().padStart(2, '0')}`;

  return <span className="timer">{display}</span>;
}
