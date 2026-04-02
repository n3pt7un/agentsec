export function SkeletonCard() {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-4 animate-pulse">
      <div className="h-4 bg-slate-700 rounded w-2/3 mb-3" />
      <div className="h-3 bg-slate-700 rounded w-1/3" />
    </div>
  );
}

export function SkeletonTable({ rows = 4 }) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden animate-pulse">
      <div className="h-10 bg-slate-700/50 border-b border-slate-700" />
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-10 border-b border-slate-700/50 flex items-center px-4 gap-4">
          <div className="h-3 bg-slate-700 rounded w-1/4" />
          <div className="h-3 bg-slate-700 rounded w-1/6" />
          <div className="h-3 bg-slate-700 rounded w-1/6" />
        </div>
      ))}
    </div>
  );
}

export function SkeletonGraph() {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-4 animate-pulse"
         style={{ height: 400 }}>
      <div className="h-4 bg-slate-700 rounded w-1/4 mb-4" />
      <div className="flex items-center justify-center h-full">
        <div className="text-slate-600 text-sm">Loading graph...</div>
      </div>
    </div>
  );
}
