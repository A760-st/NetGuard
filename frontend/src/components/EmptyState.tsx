export default function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-gray-500">
      <div className="text-4xl mb-4">◇</div>
      <p className="text-sm">{message}</p>
    </div>
  );
}
