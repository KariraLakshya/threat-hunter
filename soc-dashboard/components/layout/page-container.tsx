export default function PageContainer({
  title,
  children,
}: {
  title: string
  children: React.ReactNode
}) {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-cyan-400 tracking-wide">{title}</h1>
      {children}
    </div>
  )
}