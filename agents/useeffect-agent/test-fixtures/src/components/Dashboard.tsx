import React, { useState, useEffect } from 'react';
import { useWindowSize } from '../hooks/useWindowSize';

interface DashboardProps {
  teamId: string;
}

interface TeamStats {
  members: number;
  projects: number;
  revenue: number;
}

export function Dashboard({ teamId }: DashboardProps) {
  const [stats, setStats] = useState<TeamStats | null>(null);
  const [period, setPeriod] = useState<'week' | 'month' | 'year'>('month');
  const { width } = useWindowSize();

  // NECESSARY: Data fetching
  useEffect(() => {
    let cancelled = false;
    const url = new URL(`/api/teams/${encodeURIComponent(teamId)}/stats`, window.location.origin);
    url.searchParams.set('period', period);

    fetch(url.toString())
      .then(res => res.json())
      .then(data => {
        if (!cancelled) setStats(data);
      });

    return () => { cancelled = true; };
  }, [teamId, period]);

  // UNNECESSARY: Derived state - isMobile should be computed during render
  const [isMobile, setIsMobile] = useState(false);
  useEffect(() => {
    setIsMobile(width < 768);
  }, [width]);

  // UNNECESSARY: Derived state - formatted revenue
  const [formattedRevenue, setFormattedRevenue] = useState('$0');
  useEffect(() => {
    if (stats) {
      setFormattedRevenue(
        new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(stats.revenue)
      );
    }
  }, [stats]);

  // UNNECESSARY: Initialize from props - should use useState initializer
  const [selectedTeam, setSelectedTeam] = useState<string | null>(null);
  useEffect(() => {
    setSelectedTeam(teamId);
  }, []);

  if (!stats) return <div>Loading dashboard...</div>;

  return (
    <div className={isMobile ? 'dashboard-mobile' : 'dashboard-desktop'}>
      <div className="period-selector">
        <button onClick={() => setPeriod('week')}>Week</button>
        <button onClick={() => setPeriod('month')}>Month</button>
        <button onClick={() => setPeriod('year')}>Year</button>
      </div>
      <div className="stats-grid">
        <div className="stat">{stats.members} Members</div>
        <div className="stat">{stats.projects} Projects</div>
        <div className="stat">{formattedRevenue} Revenue</div>
      </div>
    </div>
  );
}
