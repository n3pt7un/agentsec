import { Link } from 'react-router-dom';

export default function EmptyState({ title, description, actionLabel, actionTo }) {
  return (
    <div className="text-center py-12">
      <div className="text-4xl mb-4">🛡️</div>
      <h3 className="text-lg font-semibold text-slate-300 mb-2">{title}</h3>
      <p className="text-sm text-slate-500 mb-4">{description}</p>
      {actionTo && (
        <Link to={actionTo} className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded text-sm">
          {actionLabel || 'Get Started'}
        </Link>
      )}
    </div>
  );
}
