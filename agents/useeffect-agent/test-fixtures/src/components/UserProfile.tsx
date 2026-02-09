import React, { useState, useEffect, useMemo } from 'react';

interface User {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: string;
}

interface UserProfileProps {
  userId: string;
  onUserLoad?: (user: User) => void;
}

export function UserProfile({ userId, onUserLoad }: UserProfileProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // UNNECESSARY: Derived state - fullName can be computed during render
  const [fullName, setFullName] = useState('');
  useEffect(() => {
    if (user) {
      setFullName(user.firstName + ' ' + user.lastName);
    }
  }, [user]);

  // UNNECESSARY: Notify parent - should be in the fetch handler
  useEffect(() => {
    if (user && onUserLoad) {
      onUserLoad(user);
    }
  }, [user, onUserLoad]);

  // NECESSARY: Data fetching
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    fetch(`/api/users/${userId}`)
      .then(res => {
        if (!res.ok) throw new Error('Failed to fetch user');
        return res.json();
      })
      .then(data => {
        if (!cancelled) {
          setUser(data);
          setLoading(false);
        }
      })
      .catch(err => {
        if (!cancelled) {
          setError(err.message);
          setLoading(false);
        }
      });

    return () => { cancelled = true; };
  }, [userId]);

  // UNNECESSARY: Derived state - isAdmin can be computed during render
  const [isAdmin, setIsAdmin] = useState(false);
  useEffect(() => {
    setIsAdmin(user?.role === 'admin');
  }, [user]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!user) return null;

  return (
    <div>
      <h1>{fullName}</h1>
      {isAdmin && <span className="badge">Admin</span>}
      <p>{user.email}</p>
    </div>
  );
}
