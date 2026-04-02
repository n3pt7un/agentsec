export default function ErrorState({ message, onRetry }) {
  return (
    <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-6 text-center">
      <div className="text-3xl mb-3">⚠️</div>
      <p className="text-red-300 mb-4">{message || 'Something went wrong'}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="bg-red-600 hover:bg-red-500 px-4 py-2 rounded text-sm text-white"
        >
          Try Again
        </button>
      )}
    </div>
  );
}
