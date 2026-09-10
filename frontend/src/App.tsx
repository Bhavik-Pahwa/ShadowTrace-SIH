import { FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowDownToLine,
  BarChart3,
  Bitcoin,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  Database,
  Download,
  FileText,
  Filter,
  GitBranch,
  Home,
  LineChart,
  Loader2,
  MessageSquareText,
  Network,
  RefreshCw,
  Search,
  ShieldAlert,
  Upload,
  UserCheck,
} from 'lucide-react'

import bitcoinMascotVideo from './assets/bitcoin-mascot-scrub.mp4'

type Route = 'home' | 'ingest' | 'alerts' | 'graph' | 'evidence' | 'dossier' | 'feedback'
type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | string

interface AlertItem {
  tx_id: string
  threat_score: number
  timestamp: string
  primary_anomaly: string
  risk_level: RiskLevel
}

interface AlertsResponse {
  status: 'success'
  total_count: number
  alerts: AlertItem[]
}

interface IngestResponse {
  status: 'success'
  message: string
  job_id: string
  rows_processed: number
}

interface GraphNodeData {
  id: string
  label?: string
  type?: string
  risk?: string
  risk_level?: string
  threat_score?: number
  timestamp?: string
  primary_anomaly?: string
  entity_id?: string
  country?: string
  description?: string
}

interface GraphEdgeData {
  source: string
  target: string
  relationship?: string
  amount_btc?: number
  timestamp?: string
}

interface GraphElementNode {
  data: GraphNodeData
}

interface GraphElementEdge {
  data: GraphEdgeData
}

interface GraphResponse {
  tx_id: string
  elements: {
    nodes: GraphElementNode[]
    edges: GraphElementEdge[]
  }
}

interface EvidenceFeature {
  feature: string
  value: string | number | boolean
  contribution_percentage: number
}

interface EvidenceResponse {
  tx_id: string
  overall_threat_score: number
  xai_breakdown: EvidenceFeature[]
  chain_of_custody_hash: string
}

interface DossierResponse {
  status: 'success'
  message: string
  file_path: string
  download_url: string
}

interface FeedbackResponse {
  status?: string
  message?: string
  feedback_id?: string
  recorded_timestamp?: string
}

interface FlowStep {
  id: string
  label: string
  amount?: number
  timestamp?: string
  detail?: string
}

interface GraphInsights {
  transactionCount: number
  walletCount: number
  ipCount: number
  asnCount: number
  spentEdges: GraphEdgeData[]
  receivedEdges: GraphEdgeData[]
  broadcastEdges: GraphEdgeData[]
  belongsToEdges: GraphEdgeData[]
  directInputs: FlowStep[]
  directOutputs: FlowStep[]
  exchangeOutputs: FlowStep[]
  networkSteps: FlowStep[]
  asnNodes: GraphNodeData[]
  suspiciousTxs: GraphNodeData[]
  timeline: FlowStep[]
}

interface ApiErrorShape {
  status?: string
  code?: string
  message?: string
  details?: string
}

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string
}

const SEEK_EPSILON_SECONDS = 0.025
const SCRUB_EASE = 0.12
const HERO_TEXT_FADE_START = 0.14
const HERO_TEXT_FADE_END = 0.36
const ALERT_PAGE_SIZE = 10

const FEATURE_SCENES = [
  {
    id: 'alerts',
    eyebrow: '01 / Detect',
    title: 'Catch suspicious transfers before the trail goes cold.',
    body:
      'Ingest Elliptic-style transaction data, enrich it with wallet and network signals, then surface a ranked alert queue for investigators.',
    action: 'View alerts',
    href: '#/alerts',
    enter: 0.33,
    full: 0.43,
    leave: 0.53,
  },
  {
    id: 'graph',
    eyebrow: '02 / Explain',
    title: 'Show the graph path behind every threat score.',
    body:
      'Open the full N-hop subgraph inline with transaction metadata, entity links, CIOH clusters, peel-chain hints, and XAI feature weights.',
    action: 'Inspect graph',
    href: '#/graph',
    enter: 0.52,
    full: 0.62,
    leave: 0.72,
  },
  {
    id: 'dossier',
    eyebrow: '03 / Act',
    title: 'Turn alerts into reviewable evidence.',
    body:
      'Generate a court-ready dossier, log human feedback, and prove the model can learn from confirmed cases and false positives.',
    action: 'Generate dossier',
    href: '#/dossier',
    enter: 0.71,
    full: 0.81,
    leave: 1,
  },
]

const HOME_NAV_LINKS = [
  { href: '#/ingest', label: 'Ingest' },
  { href: '#/alerts', label: 'Alerts' },
  { href: '#/graph', label: 'Graph' },
  { href: '#/evidence', label: 'XAI Evidence' },
  { href: '#/dossier', label: 'Dossier' },
]

const DASHBOARD_NAV = [
  { route: 'ingest' as const, label: 'Ingest', icon: Upload, group: 'Management' },
  { route: 'alerts' as const, label: 'Alerts', icon: ShieldAlert, group: 'Management' },
  { route: 'graph' as const, label: 'Graph', icon: Network, group: 'Management' },
  { route: 'evidence' as const, label: 'XAI Evidence', icon: BarChart3, group: 'Management' },
  { route: 'dossier' as const, label: 'Dossier', icon: FileText, group: 'System' },
  { route: 'feedback' as const, label: 'Feedback', icon: MessageSquareText, group: 'System' },
]

const SAMPLE_ALERTS: AlertItem[] = [
  {
    tx_id: 'txid_2384397f1cf2ee9641db5652',
    threat_score: 94,
    timestamp: '2026-09-08T16:22:11Z',
    primary_anomaly: 'Peel-chain cashout via bulletproof ASN',
    risk_level: 'critical',
  },
  {
    tx_id: 'txid_61dbb0137c249a1dafd8eafb',
    threat_score: 88,
    timestamp: '2026-09-08T16:25:03Z',
    primary_anomaly: 'Fan-out smurfing with Tor subnet broadcast',
    risk_level: 'high',
  },
  {
    tx_id: 'txid_a2fd6c7797d81ef672ac0148',
    threat_score: 76,
    timestamp: '2026-09-08T16:31:44Z',
    primary_anomaly: 'Shared-wallet neighborhood risk',
    risk_level: 'medium',
  },
]

const EMPTY_ASYNC = { data: null, loading: false, error: '' }

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value))
}

function smoothstep(value: number) {
  return value * value * (3 - 2 * value)
}

function sceneVisibility(progress: number, enter: number, full: number, leave: number) {
  const fadeIn = smoothstep(clamp((progress - enter) / (full - enter), 0, 1))
  const shouldStayVisible = leave >= 1

  if (shouldStayVisible) {
    return fadeIn
  }

  const fadeOut = smoothstep(clamp((progress - leave) / 0.08, 0, 1))

  return fadeIn * (1 - fadeOut)
}

function routeFromHash(hash: string): Route {
  const route = hash.replace(/^#\/?/, '') || 'home'

  if (['ingest', 'alerts', 'graph', 'evidence', 'dossier', 'feedback'].includes(route)) {
    return route as Route
  }

  return 'home'
}

async function requestJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options)
  const payload = (await response.json().catch(() => null)) as ApiErrorShape | T | null

  if (!response.ok) {
    if (response.status === 502) {
      throw new Error('Backend API is not reachable at 127.0.0.1:8000. Start the FastAPI server, then refresh this page.')
    }

    const message =
      payload && typeof payload === 'object' && 'message' in payload && payload.message
        ? `${payload.message}${payload.details ? ` ${payload.details}` : ''}`
        : `Request failed with status ${response.status}`
    throw new Error(message)
  }

  return payload as T
}

function formatNumber(value: number) {
  return new Intl.NumberFormat('en-US').format(value)
}

function formatDate(value: string) {
  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return value
  }

  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function riskTone(risk: RiskLevel) {
  const normalized = risk.toLowerCase()

  if (normalized.includes('critical')) return 'risk-critical'
  if (normalized.includes('high')) return 'risk-high'
  if (normalized.includes('medium')) return 'risk-medium'

  return 'risk-low'
}

function compactId(value: string, visible = 12) {
  if (value.length <= visible + 3) {
    return value
  }

  return `${value.slice(0, visible)}...`
}

function nodeLabel(node?: GraphNodeData) {
  if (!node) return 'Unknown node'
  if (node.label === 'IPAddress') return `${node.id}${node.country ? ` (${node.country})` : ''}`
  if (node.label === 'ASN') return node.description ? `${node.id} ${node.description}` : node.id
  if (node.label === 'WalletAddress') return `${node.type ?? 'wallet'} ${compactId(node.id, 10)}`

  return compactId(node.id, 14)
}

function buildGraphInsights(nodes: GraphElementNode[], edges: GraphElementEdge[], rootTxId: string): GraphInsights {
  const nodeMap = new Map(nodes.map((node) => [node.data.id, node.data]))
  const byLabel = (label: string) => nodes.filter((node) => node.data.label === label).length
  const edgeData = edges.map((edge) => edge.data)
  const spentEdges = edgeData.filter((edge) => edge.relationship === 'SPENT')
  const receivedEdges = edgeData.filter((edge) => edge.relationship === 'RECEIVED')
  const broadcastEdges = edgeData.filter((edge) => edge.relationship === 'BROADCAST_FROM')
  const belongsToEdges = edgeData.filter((edge) => edge.relationship === 'BELONGS_TO')
  const directInputs = spentEdges
    .filter((edge) => edge.target === rootTxId)
    .map((edge) => ({
      id: edge.source,
      label: nodeLabel(nodeMap.get(edge.source)),
      amount: edge.amount_btc,
      timestamp: edge.timestamp,
      detail: nodeMap.get(edge.source)?.entity_id,
    }))
  const directOutputs = receivedEdges
    .filter((edge) => edge.source === rootTxId)
    .map((edge) => ({
      id: edge.target,
      label: nodeLabel(nodeMap.get(edge.target)),
      amount: edge.amount_btc,
      timestamp: edge.timestamp,
      detail: nodeMap.get(edge.target)?.type,
    }))
  const exchangeOutputs = receivedEdges
    .filter((edge) => nodeMap.get(edge.target)?.type === 'exchange')
    .map((edge) => ({
      id: edge.target,
      label: nodeLabel(nodeMap.get(edge.target)),
      amount: edge.amount_btc,
      timestamp: edge.timestamp,
      detail: edge.source === rootTxId ? 'root cashout' : `from ${compactId(edge.source, 10)}`,
    }))
  const networkSteps = broadcastEdges
    .filter((edge) => edge.source === rootTxId || nodeMap.get(edge.source)?.label === 'Transaction')
    .map((edge) => ({
      id: edge.target,
      label: nodeLabel(nodeMap.get(edge.target)),
      timestamp: edge.timestamp,
      detail: edge.source === rootTxId ? 'root broadcast' : `linked broadcast from ${compactId(edge.source, 8)}`,
    }))
  const suspiciousTxs = nodes
    .map((node) => node.data)
    .filter((node) => node.label === 'Transaction')
    .sort((a, b) => (b.threat_score ?? 0) - (a.threat_score ?? 0))
  const timeline = suspiciousTxs
    .slice()
    .sort((a, b) => new Date(a.timestamp ?? '').getTime() - new Date(b.timestamp ?? '').getTime())
    .slice(-7)
    .map((node) => ({
      id: node.id,
      label: compactId(node.id, 12),
      amount: node.threat_score,
      timestamp: node.timestamp,
      detail: node.primary_anomaly,
    }))

  return {
    transactionCount: byLabel('Transaction'),
    walletCount: byLabel('WalletAddress'),
    ipCount: byLabel('IPAddress'),
    asnCount: byLabel('ASN'),
    spentEdges,
    receivedEdges,
    broadcastEdges,
    belongsToEdges,
    directInputs,
    directOutputs,
    exchangeOutputs,
    networkSteps,
    asnNodes: nodes.map((node) => node.data).filter((node) => node.label === 'ASN'),
    suspiciousTxs,
    timeline,
  }
}

function HomeNavbar() {
  return (
    <header className="floating-navbar-shell">
      <nav className="floating-navbar" aria-label="Primary navigation">
        <a className="navbar-logo" href="#/" aria-label="ShadowTrace home">
          <Bitcoin size={31} strokeWidth={2.25} />
        </a>

        <div className="navbar-links">
          {HOME_NAV_LINKS.map((link) => (
            <a key={link.href} href={link.href}>
              {link.label}
            </a>
          ))}
        </div>

        <a className="navbar-contact" href="#/feedback">
          Human Review
        </a>
      </nav>
    </header>
  )
}

function HomePage() {
  const sectionRef = useRef<HTMLElement>(null)
  const heroCopyRef = useRef<HTMLDivElement>(null)
  const featureRefs = useRef<Array<HTMLElement | null>>([])
  const videoRef = useRef<HTMLVideoElement>(null)
  const targetTimeRef = useRef(0)
  const displayedTimeRef = useRef(0)

  useEffect(() => {
    const section = sectionRef.current
    const heroCopy = heroCopyRef.current
    const video = videoRef.current

    if (!section || !heroCopy || !video) {
      return
    }

    let animationFrame = 0
    let destroyed = false
    let metadataReady = video.readyState >= 1

    const updateTargetFromScroll = () => {
      const rect = section.getBoundingClientRect()
      const scrollableDistance = Math.max(rect.height - window.innerHeight, 1)
      const progress = clamp(-rect.top / scrollableDistance, 0, 1)
      const duration = Number.isFinite(video.duration) ? video.duration : 0
      const fadeProgress = smoothstep(
        clamp((progress - HERO_TEXT_FADE_START) / (HERO_TEXT_FADE_END - HERO_TEXT_FADE_START), 0, 1),
      )

      targetTimeRef.current = duration > 0 ? progress * Math.max(duration - 0.05, 0) : 0
      heroCopy.style.setProperty('--hero-copy-opacity', String(1 - fadeProgress))
      heroCopy.style.setProperty('--hero-copy-shift', `${-28 * fadeProgress}px`)
      heroCopy.style.setProperty('--hero-copy-blur', `${2.5 * fadeProgress}px`)

      FEATURE_SCENES.forEach((scene, index) => {
        const feature = featureRefs.current[index]

        if (!feature) {
          return
        }

        const visibility = sceneVisibility(progress, scene.enter, scene.full, scene.leave)
        feature.style.setProperty('--feature-opacity', String(visibility))
        feature.style.setProperty('--feature-rise', `${34 * (1 - visibility)}px`)
        feature.style.setProperty('--feature-blur', `${3 * (1 - visibility)}px`)
      })
    }

    const renderFrame = () => {
      if (destroyed) {
        return
      }

      updateTargetFromScroll()

      const targetTime = targetTimeRef.current
      const currentTime = displayedTimeRef.current
      const nextTime = currentTime + (targetTime - currentTime) * SCRUB_EASE
      displayedTimeRef.current =
        Math.abs(targetTime - nextTime) < SEEK_EPSILON_SECONDS ? targetTime : nextTime

      if (
        metadataReady &&
        !video.seeking &&
        Math.abs(video.currentTime - displayedTimeRef.current) > SEEK_EPSILON_SECONDS
      ) {
        video.currentTime = displayedTimeRef.current
      }

      animationFrame = window.requestAnimationFrame(renderFrame)
    }

    const handleMetadata = () => {
      metadataReady = true
      displayedTimeRef.current = video.currentTime
      updateTargetFromScroll()
    }

    const handleResize = () => updateTargetFromScroll()

    video.pause()

    if (metadataReady) {
      handleMetadata()
    } else {
      video.addEventListener('loadedmetadata', handleMetadata, { once: true })
    }

    window.addEventListener('resize', handleResize)
    animationFrame = window.requestAnimationFrame(renderFrame)

    return () => {
      destroyed = true
      window.cancelAnimationFrame(animationFrame)
      window.removeEventListener('resize', handleResize)
      video.removeEventListener('loadedmetadata', handleMetadata)
    }
  }, [])

  return (
    <main className="scroll-scrub-page">
      <HomeNavbar />
      <section ref={sectionRef} className="bitcoin-hero-scroll">
        <div className="bitcoin-hero-stage">
          <div ref={heroCopyRef} className="hero-copy" aria-label="ShadowTrace-XAI introduction">
            <p className="hero-kicker">ShadowTrace-XAI</p>
            <h1>Follow the money through the chain.</h1>
            <p className="hero-subhead">Explainable crypto forensics for SIH investigators.</p>
            <p className="hero-description">
              We flag suspicious Bitcoin transactions, reveal the graph trail, and turn evidence
              into a court-ready dossier.
            </p>
          </div>

          <div className="feature-cta-layer" aria-label="ShadowTrace-XAI feature highlights">
            {FEATURE_SCENES.map((feature, index) => (
              <article
                key={feature.id}
                id={feature.id}
                ref={(node) => {
                  featureRefs.current[index] = node
                }}
                className="feature-cta"
              >
                <p className="feature-eyebrow">{feature.eyebrow}</p>
                <h2>{feature.title}</h2>
                <p>{feature.body}</p>
                <a href={feature.href}>{feature.action}</a>
              </article>
            ))}
          </div>

          <video
            ref={videoRef}
            className="bitcoin-mascot-video"
            src={bitcoinMascotVideo}
            muted
            playsInline
            preload="auto"
            aria-hidden="true"
          />
        </div>
      </section>
    </main>
  )
}

function DashboardShell({
  route,
  selectedTxId,
  alertsState,
  children,
  onRefresh,
}: {
  route: Route
  selectedTxId: string
  alertsState: AsyncState<AlertsResponse>
  children: ReactNode
  onRefresh: () => void
}) {
  const [collapsed, setCollapsed] = useState(false)
  const totalAlerts = alertsState.data?.total_count ?? SAMPLE_ALERTS.length
  const criticalCount =
    alertsState.data?.alerts.filter((alert) => alert.risk_level.toLowerCase().includes('critical')).length ?? 1

  return (
    <div className={collapsed ? 'dashboard-app sidebar-collapsed' : 'dashboard-app'}>
      <aside className="dashboard-sidebar">
        <div className="dashboard-brand">
          <a className="dashboard-brand-mark" href="#/" aria-label="Return to ShadowTrace home">
            <Bitcoin size={24} />
          </a>
          <div className="dashboard-brand-copy">
            <strong>ShadowTrace-XAI</strong>
            <span>NTRO workspace</span>
          </div>
          <button
            className="icon-button sidebar-toggle"
            type="button"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            onClick={() => setCollapsed((value) => !value)}
          >
            {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
          </button>
        </div>

        <nav className="dashboard-nav" aria-label="Dashboard navigation">
          {['Management', 'System'].map((group) => (
            <div key={group} className="dashboard-nav-group">
              <p>{group}</p>
              {DASHBOARD_NAV.filter((item) => item.group === group).map((item) => {
                const Icon = item.icon
                const active = route === item.route

                return (
                  <a
                    key={item.route}
                    className={active ? 'dashboard-nav-link active' : 'dashboard-nav-link'}
                    href={`#/${item.route}`}
                    aria-current={active ? 'page' : undefined}
                    title={item.label}
                  >
                    <Icon size={18} />
                    <span>{item.label}</span>
                  </a>
                )
              })}
            </div>
          ))}
        </nav>
      </aside>

      <div className="dashboard-frame">
        <header className="dashboard-topbar">
          <div className="dashboard-search">
            <Search size={17} />
            <span>Search transactions, entities, ASNs</span>
            <kbd>Ctrl K</kbd>
          </div>

          <div className="dashboard-actions">
            <button className="icon-button" type="button" aria-label="Refresh dashboard data" onClick={onRefresh}>
              <RefreshCw size={18} />
            </button>
            <div className="user-chip" aria-label="Active reviewer">
              <UserCheck size={17} />
              <span>investigator_demo</span>
            </div>
          </div>
        </header>

        <main className="dashboard-main">
          <div className="breadcrumbs" aria-label="Breadcrumb">
            <a href="#/">Home</a>
            <span>/</span>
            <span>{DASHBOARD_NAV.find((item) => item.route === route)?.label}</span>
          </div>

          <section className="kpi-grid" aria-label="Investigation metrics">
            <MetricCard label="Ranked alerts" value={formatNumber(totalAlerts)} trend="+39 sample run" icon={<ShieldAlert />} />
            <MetricCard label="Critical risk" value={formatNumber(criticalCount)} trend="review first" icon={<AlertTriangle />} tone="danger" />
            <MetricCard label="Selected TXID" value={selectedTxId ? selectedTxId.slice(0, 12) : 'None'} trend="shared context" icon={<CircleDot />} />
            <MetricCard label="Offline mode" value="Ready" trend="local API only" icon={<CheckCircle2 />} tone="good" />
          </section>

          {children}
        </main>
      </div>
    </div>
  )
}

function MetricCard({
  label,
  value,
  trend,
  icon,
  tone = 'neutral',
}: {
  label: string
  value: string
  trend: string
  icon: ReactNode
  tone?: 'neutral' | 'danger' | 'good'
}) {
  return (
    <article className={`metric-card ${tone}`}>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        <span>{trend}</span>
      </div>
      <div className="metric-icon" aria-hidden="true">
        {icon}
      </div>
    </article>
  )
}

function SectionHeader({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return (
    <div className="section-header">
      <p>{eyebrow}</p>
      <h1>{title}</h1>
      <span>{description}</span>
    </div>
  )
}

function StatusPanel({ state, emptyText }: { state: AsyncState<unknown>; emptyText: string }) {
  if (state.loading) {
    return (
      <div className="status-panel">
        <Loader2 className="spin" size={18} />
        <span>Loading dashboard data</span>
      </div>
    )
  }

  if (state.error) {
    return (
      <div className="status-panel warning">
        <AlertTriangle size={18} />
        <span>{state.error}</span>
      </div>
    )
  }

  return (
    <div className="status-panel">
      <Database size={18} />
      <span>{emptyText}</span>
    </div>
  )
}

function IngestPage({ onIngested }: { onIngested: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [state, setState] = useState<AsyncState<IngestResponse>>(EMPTY_ASYNC)

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    if (!file) {
      setState({ data: null, loading: false, error: 'Choose a CSV file before starting ingestion.' })
      return
    }

    const body = new FormData()
    body.append('file', file)
    setState({ data: null, loading: true, error: '' })

    try {
      const data = await requestJson<IngestResponse>('/api/ingest', { method: 'POST', body })
      setState({ data, loading: false, error: '' })
      onIngested()
    } catch (error) {
      setState({ data: null, loading: false, error: error instanceof Error ? error.message : 'Ingestion failed.' })
    }
  }

  return (
    <section className="dashboard-section">
      <SectionHeader
        eyebrow="Ingest"
        title="Upload Elliptic-style transaction data"
        description="The backend accepts multipart CSV, enriches missing wallet/network fields, builds the graph, scores alerts, and stores evidence locally."
      />

      <div className="content-grid two">
        <form className="panel ingest-panel" onSubmit={handleSubmit}>
          <label htmlFor="dataset-file">CSV dataset</label>
          <input
            id="dataset-file"
            type="file"
            accept=".csv,text/csv"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
          <button className="primary-action" type="submit" disabled={state.loading}>
            {state.loading ? <Loader2 className="spin" size={18} /> : <Upload size={18} />}
            Run ingest pipeline
          </button>
          {state.data ? (
            <div className="success-box" role="status">
              <CheckCircle2 size={18} />
              <span>
                {state.data.message} Job {state.data.job_id} processed {formatNumber(state.data.rows_processed)} rows.
              </span>
            </div>
          ) : (
            <StatusPanel state={state} emptyText="No upload has been submitted in this browser session." />
          )}
        </form>

        <article className="panel contract-panel">
          <h2>Pipeline contract</h2>
          <ul>
            <li>CSV ingestion through Polars and DuckDB persistence.</li>
            <li>Local graph construction with Transaction, WalletAddress, IPAddress, and ASN nodes.</li>
            <li>GCN scoring, GNNExplainer subgraphs, and SHAP-style contribution rows.</li>
            <li>Zero external lookups at runtime; GeoIP enrichment is local-only.</li>
          </ul>
        </article>
      </div>
    </section>
  )
}

function AlertsPage({
  alertsState,
  selectedTxId,
  offset,
  onOffsetChange,
  onSelect,
  onRefresh,
}: {
  alertsState: AsyncState<AlertsResponse>
  selectedTxId: string
  offset: number
  onOffsetChange: (offset: number) => void
  onSelect: (txId: string) => void
  onRefresh: () => void
}) {
  const alerts = alertsState.data?.alerts.length ? alertsState.data.alerts : SAMPLE_ALERTS
  const total = alertsState.data?.total_count ?? SAMPLE_ALERTS.length

  return (
    <section className="dashboard-section">
      <SectionHeader
        eyebrow="Alerts"
        title="Ranked suspicious transaction queue"
        description="Alerts are paginated by the API and include only the PRD-approved fields: TXID, score, timestamp, primary anomaly, and risk level."
      />

      <div className="table-toolbar">
        <div>
          <Filter size={17} />
          <span>{alertsState.data ? `${formatNumber(total)} backend alerts` : 'Sample rows shown until backend data loads'}</span>
        </div>
        <button className="secondary-action" type="button" onClick={onRefresh}>
          <RefreshCw size={17} />
          Refresh
        </button>
      </div>

      <div className="panel table-panel">
        <table>
          <thead>
            <tr>
              <th>TXID</th>
              <th>Threat score</th>
              <th>Risk</th>
              <th>Primary anomaly</th>
              <th>Timestamp</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.tx_id} className={selectedTxId === alert.tx_id ? 'selected-row' : undefined}>
                <td className="mono">{alert.tx_id}</td>
                <td>
                  <div className="score-meter">
                    <span style={{ width: `${clamp(alert.threat_score, 0, 100)}%` }} />
                  </div>
                  {alert.threat_score}
                </td>
                <td>
                  <span className={`risk-pill ${riskTone(alert.risk_level)}`}>{alert.risk_level}</span>
                </td>
                <td>{alert.primary_anomaly}</td>
                <td>{formatDate(alert.timestamp)}</td>
                <td>
                  <button className="row-action" type="button" onClick={() => onSelect(alert.tx_id)}>
                    Inspect
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!alerts.length && <StatusPanel state={alertsState} emptyText="No results found." />}
      </div>

      <div className="pagination-row">
        <button className="secondary-action" type="button" disabled={offset === 0} onClick={() => onOffsetChange(Math.max(0, offset - ALERT_PAGE_SIZE))}>
          <ChevronLeft size={17} />
          Previous
        </button>
        <span>
          {formatNumber(offset + 1)}-{formatNumber(Math.min(offset + ALERT_PAGE_SIZE, total))} of {formatNumber(total)}
        </span>
        <button
          className="secondary-action"
          type="button"
          disabled={offset + ALERT_PAGE_SIZE >= total}
          onClick={() => onOffsetChange(offset + ALERT_PAGE_SIZE)}
        >
          Next
          <ChevronRight size={17} />
        </button>
      </div>
    </section>
  )
}

function GraphPage({
  txId,
  graphState,
  onTxIdChange,
  onLoad,
}: {
  txId: string
  graphState: AsyncState<GraphResponse>
  onTxIdChange: (txId: string) => void
  onLoad: () => void
}) {
  const graph = graphState.data?.elements
  const nodeCount = graph?.nodes.length ?? 0
  const edgeCount = graph?.edges.length ?? 0
  const insights = graph ? buildGraphInsights(graph.nodes, graph.edges, graphState.data?.tx_id ?? txId) : null

  return (
    <section className="dashboard-section">
      <SectionHeader
        eyebrow="Graph"
        title="N-hop transaction graph explorer"
        description="The frontend consumes the full server-side graph payload in one request, with inline node and edge metadata."
      />

      <TxLookup txId={txId} onTxIdChange={onTxIdChange} onLoad={onLoad} loading={graphState.loading} actionLabel="Load graph" />

      {insights && <GraphInsightStrip insights={insights} />}

      <div className="content-grid graph-layout">
        <article className="panel graph-canvas-panel">
          {graph && insights ? (
            <GraphCanvas nodes={graph.nodes} edges={graph.edges} rootTxId={graphState.data?.tx_id ?? txId} insights={insights} />
          ) : (
            <StatusPanel state={graphState} emptyText="Select an alert or enter a TXID to render the graph." />
          )}
        </article>

        <article className="panel metadata-panel">
          <h2>What to investigate</h2>
          <dl>
            <div>
              <dt>Graph size</dt>
              <dd>{nodeCount} nodes / {edgeCount} edges</dd>
            </div>
            <div>
              <dt>Exchange outputs</dt>
              <dd>{insights?.exchangeOutputs.length ?? 0}</dd>
            </div>
            <div>
              <dt>Network cluster</dt>
              <dd>{insights?.asnNodes[0] ? compactId(nodeLabel(insights.asnNodes[0]), 28) : 'None'}</dd>
            </div>
          </dl>
          {insights ? <GraphFindings insights={insights} /> : <p className="muted-copy">No graph loaded yet.</p>}
        </article>
      </div>

      {insights && <GraphEvidenceTables insights={insights} />}
    </section>
  )
}

function EvidencePage({
  txId,
  evidenceState,
  onTxIdChange,
  onLoad,
}: {
  txId: string
  evidenceState: AsyncState<EvidenceResponse>
  onTxIdChange: (txId: string) => void
  onLoad: () => void
}) {
  const evidence = evidenceState.data

  return (
    <section className="dashboard-section">
      <SectionHeader
        eyebrow="XAI Evidence"
        title="Threat score attribution"
        description="Evidence is scoped to the root flagged transaction and each contribution row sums exactly to the overall threat score."
      />

      <TxLookup txId={txId} onTxIdChange={onTxIdChange} onLoad={onLoad} loading={evidenceState.loading} actionLabel="Load evidence" />

      <div className="content-grid two">
        <article className="panel evidence-chart-panel">
          {evidence ? (
            <>
              <div className="radial-score" style={{ '--score': evidence.overall_threat_score } as React.CSSProperties}>
                <strong>{evidence.overall_threat_score}</strong>
                <span>overall score</span>
              </div>
              <p className="hash-line">
                Custody hash <span>{evidence.chain_of_custody_hash}</span>
              </p>
            </>
          ) : (
            <StatusPanel state={evidenceState} emptyText="Load a flagged TXID to view XAI attribution." />
          )}
        </article>

        <article className="panel attribution-panel">
          <h2>Feature contribution</h2>
          {evidence ? (
            <div className="attribution-list">
              {evidence.xai_breakdown.map((feature) => (
                <div key={feature.feature} className="attribution-row">
                  <div>
                    <strong>{feature.feature}</strong>
                    <span>{String(feature.value)}</span>
                  </div>
                  <div className="mini-meter" aria-label={`${feature.contribution_percentage} percent contribution`}>
                    <span style={{ width: `${clamp(feature.contribution_percentage, 0, 100)}%` }} />
                  </div>
                  <b>{feature.contribution_percentage}</b>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted-copy">No Data Found</p>
          )}
        </article>
      </div>
    </section>
  )
}

function DossierPage({
  txId,
  dossierState,
  onTxIdChange,
  onGenerate,
}: {
  txId: string
  dossierState: AsyncState<DossierResponse>
  onTxIdChange: (txId: string) => void
  onGenerate: (includeXai: boolean, includeNetwork: boolean) => void
}) {
  const [includeXai, setIncludeXai] = useState(true)
  const [includeNetwork, setIncludeNetwork] = useState(true)
  const downloadHref = dossierState.data?.download_url

  return (
    <section className="dashboard-section">
      <SectionHeader
        eyebrow="Dossier"
        title="Court-ready evidence export"
        description="Generate a local PDF dossier with agency header, graph visualization, attribution table, network metadata, and custody hash."
      />

      <div className="content-grid two">
        <article className="panel dossier-panel">
          <label htmlFor="dossier-tx">Flagged TXID</label>
          <input id="dossier-tx" value={txId} onChange={(event) => onTxIdChange(event.target.value)} placeholder="txid_..." />
          <label className="check-row">
            <input type="checkbox" checked={includeXai} onChange={(event) => setIncludeXai(event.target.checked)} />
            Include XAI visualization
          </label>
          <label className="check-row">
            <input type="checkbox" checked={includeNetwork} onChange={(event) => setIncludeNetwork(event.target.checked)} />
            Include network metadata
          </label>
          <button className="primary-action" type="button" disabled={dossierState.loading} onClick={() => onGenerate(includeXai, includeNetwork)}>
            {dossierState.loading ? <Loader2 className="spin" size={18} /> : <FileText size={18} />}
            Generate dossier
          </button>
        </article>

        <article className="panel dossier-result">
          {dossierState.data && downloadHref ? (
            <>
              <CheckCircle2 size={28} />
              <h2>{dossierState.data.message}</h2>
              <p className="muted-copy">Server file: {dossierState.data.file_path}</p>
              <a className="primary-action" href={downloadHref} download>
                <Download size={18} />
                Download PDF
              </a>
            </>
          ) : (
            <StatusPanel state={dossierState} emptyText="No dossier has been generated in this browser session." />
          )}
        </article>
      </div>
    </section>
  )
}

function FeedbackPage({
  selectedTxId,
  latestAlert,
}: {
  selectedTxId: string
  latestAlert: AlertItem | null
}) {
  const [label, setLabel] = useState(1)
  const [state, setState] = useState<AsyncState<FeedbackResponse>>(EMPTY_ASYNC)

  const submitFeedback = async () => {
    if (!selectedTxId) {
      setState({ data: null, loading: false, error: 'Select a transaction before sending feedback.' })
      return
    }

    setState({ data: null, loading: true, error: '' })

    try {
      const data = await requestJson<FeedbackResponse>('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tx_id: selectedTxId,
          ai_score: latestAlert ? latestAlert.threat_score / 100 : 0,
          human_label: label,
          reviewed_by: 'investigator_demo',
        }),
      })
      setState({ data, loading: false, error: '' })
    } catch (error) {
      setState({ data: null, loading: false, error: error instanceof Error ? error.message : 'Feedback failed.' })
    }
  }

  return (
    <section className="dashboard-section">
      <SectionHeader
        eyebrow="Feedback"
        title="Human-in-the-loop review"
        description="Record investigator labels against the selected alert for the active-learning demo loop."
      />

      <div className="content-grid two">
        <article className="panel feedback-panel">
          <label htmlFor="feedback-label">Human label</label>
          <select id="feedback-label" value={label} onChange={(event) => setLabel(Number(event.target.value))}>
            <option value={1}>Confirmed illicit</option>
            <option value={0}>False positive</option>
          </select>
          <button className="primary-action" type="button" disabled={state.loading} onClick={submitFeedback}>
            {state.loading ? <Loader2 className="spin" size={18} /> : <MessageSquareText size={18} />}
            Submit review
          </button>
        </article>

        <article className="panel feedback-summary">
          <h2>Review target</h2>
          <p className="mono">{selectedTxId || 'No transaction selected'}</p>
          {state.data ? (
            <div className="success-box">
              <CheckCircle2 size={18} />
              <span>{state.data.message ?? 'Feedback recorded.'}</span>
            </div>
          ) : (
            <StatusPanel state={state} emptyText="No review submitted yet." />
          )}
        </article>
      </div>
    </section>
  )
}

function TxLookup({
  txId,
  onTxIdChange,
  onLoad,
  loading,
  actionLabel,
}: {
  txId: string
  onTxIdChange: (txId: string) => void
  onLoad: () => void
  loading: boolean
  actionLabel: string
}) {
  return (
    <div className="lookup-bar">
      <label htmlFor="tx-lookup">Transaction ID</label>
      <input id="tx-lookup" value={txId} onChange={(event) => onTxIdChange(event.target.value)} placeholder="txid_..." />
      <button className="primary-action" type="button" onClick={onLoad} disabled={loading || !txId.trim()}>
        {loading ? <Loader2 className="spin" size={18} /> : <Search size={18} />}
        {actionLabel}
      </button>
    </div>
  )
}

function GraphInsightStrip({ insights }: { insights: GraphInsights }) {
  const exchangeAmount = insights.exchangeOutputs.reduce((sum, output) => sum + (output.amount ?? 0), 0)
  const rootBroadcast = insights.networkSteps.find((step) => step.detail === 'root broadcast')
  const strongestTx = insights.suspiciousTxs[0]

  return (
    <div className="graph-insight-strip" aria-label="Graph investigative summary">
      <article>
        <ArrowDownToLine size={19} />
        <div>
          <strong>{insights.directInputs.length} funding input{insights.directInputs.length === 1 ? '' : 's'}</strong>
          <span>{insights.spentEdges.length} SPENT edges in local neighborhood</span>
        </div>
      </article>
      <article>
        <LineChart size={19} />
        <div>
          <strong>{insights.timeline.length} timed risky hops</strong>
          <span>{strongestTx ? `${strongestTx.threat_score ?? 0}/100 top score` : 'No risky hop detected'}</span>
        </div>
      </article>
      <article>
        <Database size={19} />
        <div>
          <strong>{exchangeAmount.toFixed(4)} BTC to exchanges</strong>
          <span>{insights.exchangeOutputs.length} terminal exchange wallet{insights.exchangeOutputs.length === 1 ? '' : 's'}</span>
        </div>
      </article>
      <article>
        <GitBranch size={19} />
        <div>
          <strong>{rootBroadcast?.label ?? `${insights.ipCount} broadcast IPs`}</strong>
          <span>{insights.asnNodes[0] ? nodeLabel(insights.asnNodes[0]) : 'No ASN concentration'}</span>
        </div>
      </article>
    </div>
  )
}

function GraphFindings({ insights }: { insights: GraphInsights }) {
  const exchangeAmount = insights.exchangeOutputs.reduce((sum, output) => sum + (output.amount ?? 0), 0)
  const rootOutput = insights.directOutputs.find((output) => output.detail === 'change') ?? insights.directOutputs[0]
  const rootExchange = insights.directOutputs.find((output) => output.detail === 'exchange')
  const asn = insights.asnNodes[0]

  return (
    <div className="finding-list">
      <article>
        <strong>Money movement</strong>
        <span>
          Root transaction spends {insights.directInputs[0]?.amount?.toFixed(4) ?? 'unknown'} BTC and sends{' '}
          {rootOutput?.amount?.toFixed(4) ?? 'unknown'} BTC onward{rootExchange ? `, with ${rootExchange.amount?.toFixed(4)} BTC directly to an exchange wallet` : ''}.
        </span>
      </article>
      <article>
        <strong>Cashout pattern</strong>
        <span>
          {insights.exchangeOutputs.length} exchange outputs appear in the N-hop payload, totaling {exchangeAmount.toFixed(4)} BTC.
        </span>
      </article>
      <article>
        <strong>Network signal</strong>
        <span>
          {insights.ipCount} broadcast IPs map through {insights.belongsToEdges.length} ASN links
          {asn ? ` into ${nodeLabel(asn)}` : ''}.
        </span>
      </article>
    </div>
  )
}

function GraphEvidenceTables({ insights }: { insights: GraphInsights }) {
  const outputRows = insights.exchangeOutputs.length ? insights.exchangeOutputs : insights.directOutputs

  return (
    <div className="content-grid two graph-detail-grid">
      <article className="panel compact-table-panel">
        <h2>Money edges worth checking</h2>
        <table>
          <thead>
            <tr>
              <th>Target</th>
              <th>Amount BTC</th>
              <th>Timestamp</th>
              <th>Meaning</th>
            </tr>
          </thead>
          <tbody>
            {outputRows.slice(0, 8).map((row) => (
              <tr key={`${row.id}-${row.amount}-${row.timestamp}`}>
                <td className="mono">{row.label}</td>
                <td>{row.amount?.toFixed(4) ?? 'n/a'}</td>
                <td>{row.timestamp ? formatDate(row.timestamp) : 'n/a'}</td>
                <td>{row.detail ?? 'output'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </article>

      <article className="panel compact-table-panel">
        <h2>Network edges worth checking</h2>
        <table>
          <thead>
            <tr>
              <th>Broadcast IP</th>
              <th>Time</th>
              <th>Relationship</th>
            </tr>
          </thead>
          <tbody>
            {insights.networkSteps.slice(0, 8).map((row) => (
              <tr key={`${row.id}-${row.timestamp}-${row.detail}`}>
                <td className="mono">{row.label}</td>
                <td>{row.timestamp ? formatDate(row.timestamp) : 'n/a'}</td>
                <td>{row.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </article>
    </div>
  )
}

function GraphCanvas({
  nodes,
  edges,
  rootTxId,
  insights,
}: {
  nodes: GraphElementNode[]
  edges: GraphElementEdge[]
  rootTxId: string
  insights: GraphInsights
}) {
  const width = 980
  const height = 560
  const nodeMap = new Map(nodes.map((node) => [node.data.id, node.data]))
  const positions = new Map<string, { x: number; y: number; lane: string; title: string; subtitle: string }>()
  const rootNode = nodeMap.get(rootTxId)
  const incoming = insights.directInputs.slice(0, 4)
  const outputs = insights.directOutputs.slice(0, 5)
  const network = insights.networkSteps.slice(0, 5)
  const asn = insights.asnNodes.slice(0, 2)
  const timeline = insights.timeline.filter((step) => step.id !== rootTxId).slice(-5)
  const visibleIds = new Set<string>([rootTxId])

  const placeColumn = (items: FlowStep[], x: number, lane: string, startY: number, gap: number) => {
    items.forEach((item, index) => {
      visibleIds.add(item.id)
      positions.set(item.id, {
        x,
        y: startY + index * gap,
        lane,
        title: item.label,
        subtitle: item.amount !== undefined ? `${item.amount.toFixed(4)} BTC` : item.detail ?? '',
      })
    })
  }

  placeColumn(incoming, 130, 'input', 210, 72)
  placeColumn(timeline, 360, 'transaction', 128, 62)
  placeColumn(outputs, 720, 'wallet', 160, 66)
  placeColumn(network, 720, 'network', 390, 42)
  asn.forEach((node, index) => {
    visibleIds.add(node.id)
    positions.set(node.id, {
      x: 890,
      y: 410 + index * 66,
      lane: 'asn',
      title: node.id,
      subtitle: compactId(node.description ?? 'ASN infrastructure', 24),
    })
  })
  positions.set(rootTxId, {
    x: 520,
    y: 280,
    lane: 'root',
    title: compactId(rootTxId, 16),
    subtitle: `${rootNode?.threat_score ?? 'n/a'}/100 ${rootNode?.primary_anomaly ?? 'risk'}`,
  })

  const visibleEdges = edges
    .map((edge) => edge.data)
    .filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target))
    .slice(0, 42)

  return (
    <svg className="graph-canvas insight-graph" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Readable transaction flow visualization">
      <defs>
        <marker id="dashboard-arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
          <path d="M0,0 L0,6 L9,3 z" />
        </marker>
      </defs>
      <g className="lane-labels">
        <text x="130" y="64">Inputs</text>
        <text x="360" y="64">Prior risky hops</text>
        <text x="520" y="64">Root alert</text>
        <text x="720" y="64">Outputs + broadcast</text>
        <text x="890" y="64">ASN</text>
      </g>
      <path className="flow-band" d="M130 280 C270 280, 380 280, 496 280" />
      <path className="flow-band output" d="M544 280 C620 250, 650 210, 696 190" />
      <path className="flow-band network" d="M544 280 C620 330, 650 392, 696 410" />
      {visibleEdges.map((edge, index) => {
        const source = positions.get(edge.source)
        const target = positions.get(edge.target)

        if (!source || !target) {
          return null
        }

        return (
          <g key={`${edge.source}-${edge.target}-${index}`} className={`edge-${edge.relationship}`}>
            <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} />
            {edge.amount_btc !== undefined && (
              <text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 6}>
                {edge.amount_btc.toFixed(4)} BTC
              </text>
            )}
          </g>
        )
      })}
      {Array.from(positions.entries()).map(([id, position]) => {
        const node = nodeMap.get(id)
        const type = node?.label ?? position.lane
        const isRoot = id === rootTxId

        return (
          <g key={id} className={isRoot ? 'root-node flow-node' : `flow-node lane-${position.lane}`}>
            <rect x={position.x - (isRoot ? 84 : 70)} y={position.y - 24} width={isRoot ? 168 : 140} height={48} rx={8} />
            <text x={position.x} y={position.y - 4} className="node-label">
              {isRoot ? 'Root transaction' : type}
            </text>
            <text x={position.x} y={position.y + 13} className="node-id">
              {position.subtitle || position.title}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

function DashboardApp({ route }: { route: Exclude<Route, 'home'> }) {
  const [alertsState, setAlertsState] = useState<AsyncState<AlertsResponse>>(EMPTY_ASYNC)
  const [graphState, setGraphState] = useState<AsyncState<GraphResponse>>(EMPTY_ASYNC)
  const [evidenceState, setEvidenceState] = useState<AsyncState<EvidenceResponse>>(EMPTY_ASYNC)
  const [dossierState, setDossierState] = useState<AsyncState<DossierResponse>>(EMPTY_ASYNC)
  const [offset, setOffset] = useState(0)
  const [selectedTxId, setSelectedTxId] = useState(SAMPLE_ALERTS[0].tx_id)

  const latestAlert = useMemo(() => {
    return alertsState.data?.alerts.find((alert) => alert.tx_id === selectedTxId) ?? SAMPLE_ALERTS.find((alert) => alert.tx_id === selectedTxId) ?? null
  }, [alertsState.data, selectedTxId])

  const loadAlerts = async (nextOffset = offset) => {
    setAlertsState((current) => ({ ...current, loading: true, error: '' }))

    try {
      const data = await requestJson<AlertsResponse>(`/api/alerts?limit=${ALERT_PAGE_SIZE}&offset=${nextOffset}`)
      setAlertsState({ data, loading: false, error: '' })
      if (data.alerts[0] && !selectedTxId) {
        setSelectedTxId(data.alerts[0].tx_id)
      }
    } catch (error) {
      setAlertsState({
        data: null,
        loading: false,
        error: error instanceof Error ? error.message : 'Could not load alerts.',
      })
    }
  }

  const loadGraph = async () => {
    if (!selectedTxId.trim()) return
    setGraphState({ data: null, loading: true, error: '' })

    try {
      const data = await requestJson<GraphResponse>(`/api/graph/${encodeURIComponent(selectedTxId.trim())}`)
      setGraphState({ data, loading: false, error: '' })
    } catch (error) {
      setGraphState({ data: null, loading: false, error: error instanceof Error ? error.message : 'Could not load graph.' })
    }
  }

  const loadEvidence = async () => {
    if (!selectedTxId.trim()) return
    setEvidenceState({ data: null, loading: true, error: '' })

    try {
      const data = await requestJson<EvidenceResponse>(`/api/evidence/${encodeURIComponent(selectedTxId.trim())}`)
      setEvidenceState({ data, loading: false, error: '' })
    } catch (error) {
      setEvidenceState({ data: null, loading: false, error: error instanceof Error ? error.message : 'Could not load evidence.' })
    }
  }

  const generateDossier = async (includeXai: boolean, includeNetwork: boolean) => {
    if (!selectedTxId.trim()) {
      setDossierState({ data: null, loading: false, error: 'Select a flagged transaction before generating a dossier.' })
      return
    }

    setDossierState({ data: null, loading: true, error: '' })

    try {
      const data = await requestJson<DossierResponse>('/api/generate-dossier', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tx_id: selectedTxId.trim(),
          investigator_id: 'investigator_demo',
          include_xai_visuals: includeXai,
          include_network_metadata: includeNetwork,
        }),
      })
      setDossierState({ data, loading: false, error: '' })
    } catch (error) {
      setDossierState({ data: null, loading: false, error: error instanceof Error ? error.message : 'Could not generate dossier.' })
    }
  }

  useEffect(() => {
    loadAlerts(0)
  }, [])

  useEffect(() => {
    if (route === 'graph') loadGraph()
    if (route === 'evidence') loadEvidence()
  }, [route])

  const handleOffsetChange = (nextOffset: number) => {
    setOffset(nextOffset)
    loadAlerts(nextOffset)
  }

  const selectAlert = (txId: string) => {
    setSelectedTxId(txId)
    window.location.hash = '#/graph'
  }

  return (
    <DashboardShell route={route} selectedTxId={selectedTxId} alertsState={alertsState} onRefresh={() => loadAlerts(offset)}>
      {route === 'ingest' && <IngestPage onIngested={() => loadAlerts(0)} />}
      {route === 'alerts' && (
        <AlertsPage
          alertsState={alertsState}
          selectedTxId={selectedTxId}
          offset={offset}
          onOffsetChange={handleOffsetChange}
          onSelect={selectAlert}
          onRefresh={() => loadAlerts(offset)}
        />
      )}
      {route === 'graph' && <GraphPage txId={selectedTxId} graphState={graphState} onTxIdChange={setSelectedTxId} onLoad={loadGraph} />}
      {route === 'evidence' && <EvidencePage txId={selectedTxId} evidenceState={evidenceState} onTxIdChange={setSelectedTxId} onLoad={loadEvidence} />}
      {route === 'dossier' && <DossierPage txId={selectedTxId} dossierState={dossierState} onTxIdChange={setSelectedTxId} onGenerate={generateDossier} />}
      {route === 'feedback' && <FeedbackPage selectedTxId={selectedTxId} latestAlert={latestAlert} />}
    </DashboardShell>
  )
}

function App() {
  const [route, setRoute] = useState<Route>(() => routeFromHash(window.location.hash))

  useEffect(() => {
    const handleHashChange = () => setRoute(routeFromHash(window.location.hash))
    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])

  if (route === 'home') {
    return <HomePage />
  }

  return <DashboardApp route={route} />
}

export default App
