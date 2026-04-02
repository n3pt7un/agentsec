import { useState, useEffect } from 'react';

export function useActiveSection(sectionIds) {
  const [activeId, setActiveId] = useState(sectionIds[0] ?? null);

  useEffect(() => {
    if (sectionIds.length === 0) return;

    const observers = sectionIds.map(id => {
      const el = document.getElementById(id);
      if (!el) return null;
      const obs = new IntersectionObserver(
        ([entry]) => { if (entry.isIntersecting) setActiveId(id); },
        { threshold: 0.2, rootMargin: '-10% 0px -70% 0px' }
      );
      obs.observe(el);
      return obs;
    });

    return () => observers.forEach(o => o?.disconnect());
  }, [sectionIds.join(',')]); // eslint-disable-line react-hooks/exhaustive-deps

  return activeId;
}
