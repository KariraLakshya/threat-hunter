import PageContainer from "@/components/layout/page-container"
import KPICards from "@/components/overview/kpi-cards"
import TrendsPanel from "@/components/overview/trends-panel"
import HealthPanel from "@/components/overview/health-panel"

export default function OverviewPage() {
  return (
    <PageContainer title="Overview">
      <KPICards />
      <TrendsPanel />
      <HealthPanel />
    </PageContainer>
  )
}