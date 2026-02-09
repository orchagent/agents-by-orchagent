import React, { useState, useEffect } from 'react';

interface Product {
  id: string;
  name: string;
  category: string;
  price: number;
  inStock: boolean;
}

interface SearchFilterProps {
  products: Product[];
  onFilterChange?: (filtered: Product[]) => void;
}

export function SearchFilter({ products, onFilterChange }: SearchFilterProps) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<string>('all');
  const [minPrice, setMinPrice] = useState(0);
  const [maxPrice, setMaxPrice] = useState(Infinity);

  // UNNECESSARY: Derived state - filteredProducts should be computed during render
  const [filteredProducts, setFilteredProducts] = useState<Product[]>([]);
  useEffect(() => {
    const filtered = products.filter(p => {
      const matchesQuery = p.name.toLowerCase().includes(query.toLowerCase());
      const matchesCategory = category === 'all' || p.category === category;
      const matchesPrice = p.price >= minPrice && p.price <= maxPrice;
      return matchesQuery && matchesCategory && matchesPrice;
    });
    setFilteredProducts(filtered);
  }, [products, query, category, minPrice, maxPrice]);

  // UNNECESSARY: Notify parent - chained from the derived state above
  useEffect(() => {
    if (onFilterChange) {
      onFilterChange(filteredProducts);
    }
  }, [filteredProducts, onFilterChange]);

  // UNNECESSARY: Derived state - categories can be computed during render
  const [categories, setCategories] = useState<string[]>([]);
  useEffect(() => {
    const uniqueCategories = [...new Set(products.map(p => p.category))];
    setCategories(uniqueCategories);
  }, [products]);

  // UNNECESSARY: Derived state - result count
  const [resultCount, setResultCount] = useState(0);
  useEffect(() => {
    setResultCount(filteredProducts.length);
  }, [filteredProducts]);

  return (
    <div>
      <input
        type="text"
        value={query}
        onChange={e => setQuery(e.target.value)}
        placeholder="Search products..."
      />
      <select value={category} onChange={e => setCategory(e.target.value)}>
        <option value="all">All Categories</option>
        {categories.map(cat => (
          <option key={cat} value={cat}>{cat}</option>
        ))}
      </select>
      <div>
        <input type="number" value={minPrice} onChange={e => setMinPrice(Number(e.target.value))} />
        <input type="number" value={maxPrice === Infinity ? '' : maxPrice} onChange={e => setMaxPrice(Number(e.target.value) || Infinity)} />
      </div>
      <p>{resultCount} results</p>
      <ul>
        {filteredProducts.map(p => (
          <li key={p.id}>{p.name} - ${p.price}</li>
        ))}
      </ul>
    </div>
  );
}
