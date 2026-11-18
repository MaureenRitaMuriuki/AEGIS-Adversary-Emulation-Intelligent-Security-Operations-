import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Activity, AlertOctagon, ArrowDownRight, ArrowUpRight, Bell, Check,
  ChevronDown, CircleHelp, Clock3, Command, Cpu, Database, FileSearch,
  Fingerprint, LayoutDashboard, ListFilter, LockKeyhole, Menu, RefreshCw,
  Search, Server, Settings2, Shield, ShieldAlert, ShieldCheck, Signal,
  SlidersHorizontal, TerminalSquare, X
} from "lucide-react";

type EventRecord = {
  event_id: string; timestamp: string; source: string; event_type: string;
  host: string; username?: string | null; process_name?: string | null;
  command_line?: string | null; source_ip?: string | null;
};
type AlertRecord = {
  alert_id: string; rule_id: string; title: string; severity: string;
  description: string; event_ids: string[]; mitre_techniques: string[];
  created_at: string; status: "new" | "acknowledged" | "resolved"; analyst_note: string;
};
type Page = "overview" | "events" | "alerts";

const timeAgo = (value?: string) => {
  if (!value) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return seconds + "s ago";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
  return Math.floor(seconds / 86400) + "d ago";
};
const stamp = (value?: string) => value ? new Date(value).toLocaleString() : "—";

function App() {
  const [page, setPage] = useState<Page>("overview");
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [online, setOnline] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastSync, setLastSync] = useState<Date | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const [query, setQuery] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [healthRes, eventsRes, alertsRes] = await Promise.all([
        fetch("/health"), fetch("/api/v1/events?limit=100"), fetch("/api/v1/alerts?limit=100")
      ]);
      if (!healthRes.ok || !eventsRes.ok || !alertsRes.ok) throw new Error("API request failed");
      const [health, eventData, alertData] = await Promise.all([
        healthRes.json(), eventsRes.json(), alertsRes.json()
      ]);
      setOnline(health.status === "ok");
      setEvents(eventData.items ?? []);
      setAlerts(alertData.items ?? []);
      setLastSync(new Date());
    } catch {
      setOnline(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const updateAlert = useCallback(async (alertId: string, status: AlertRecord["status"], analystNote: string) => {
    const response = await fetch(`/api/v1/alerts/${alertId}/status`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, analyst_note: analystNote })
    });
    if (!response.ok) throw new Error("Could not update alert status");
    await refresh();
  }, [refresh]);

  const filteredEvents = useMemo(() => events.filter((event) =>
    [event.host, event.source, event.event_type, event.username, event.process_name]
      .some((value) => value?.toLowerCase().includes(query.toLowerCase()))
  ), [events, query]);

  const filteredAlerts = useMemo(() => alerts.filter((alert) =>
    [alert.title, alert.rule_id, alert.severity, alert.description, alert.status, alert.analyst_note]
      .some((value) => value?.toLowerCase().includes(query.toLowerCase()))
  ), [alerts, query]);

  const criticalCount = alerts.filter((a) => a.severity.toLowerCase() === "critical").length;
  const highCount = alerts.filter((a) => a.severity.toLowerCase() === "high").length;
  const mediumCount = alerts.filter((a) => a.severity.toLowerCase() === "medium").length;

  const navItems = [
    { id: "overview" as Page, label: "Overview", icon: LayoutDashboard },
    { id: "events" as Page, label: "Event stream", icon: Activity, count: events.length },
    { id: "alerts" as Page, label: "Detection alerts", icon: ShieldAlert, count: alerts.length }
  ];

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={22} strokeWidth={1.7} /></div>
          <div><div className="brand-name">AEGIS</div><div className="brand-sub">SECURITY OPERATIONS</div></div>
          <button className="icon-button mobile-close" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={18}/></button>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <div className="nav-list">
          {navItems.map((item) => {
            const Icon = item.icon;
            return <button key={item.id} className={`nav-item ${page === item.id ? "active" : ""}`} onClick={() => { setPage(item.id); setMobileNav(false); }}>
              <Icon size={18}/><span>{item.label}</span>{item.count !== undefined && <span className="nav-count">{item.count}</span>}
            </button>;
          })}
        </div>
        <div className="workspace-label section-label">OPERATIONS</div>
        <div className="nav-list">
          <button className="nav-item muted" onClick={() => setPage("events")}><FileSearch size={18}/><span>Investigations</span><span className="soon">IN VIEW</span></button>
          <button className="nav-item muted" onClick={() => setPage("alerts")}><Fingerprint size={18}/><span>Detection rules</span></button>
          <button className="nav-item muted" onClick={() => setPage("events")}><TerminalSquare size={18}/><span>Adversary lab</span></button>
        </div>
        <div className="sidebar-bottom">
          <div className="system-card">
            <div className="system-card-top"><span className={`status-dot ${online ? "online" : "offline"}`}></span><span>API CONNECTION</span></div>
            <div className="system-card-value">{online ? "Connected" : "Unavailable"}</div>
            <div className="system-card-foot">{online ? "FastAPI · SQLite" : "Start the AEGIS API to connect"}</div>
          </div>
          <button className="nav-item muted"><Settings2 size={18}/><span>Settings</span></button>
          <div className="profile">
            <div className="avatar">MR</div>
            <div className="profile-copy"><strong>Maureen Rita</strong><span>System Administrator</span></div>
            <ChevronDown size={15} className="profile-chevron"/>
          </div>
        </div>
      </aside>

      {mobileNav && <button className="scrim" onClick={() => setMobileNav(false)} aria-label="Close menu"/>}
      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button menu-button" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={19}/></button>
            <div className="breadcrumb">AEGIS <span>/</span> <strong>{page === "overview" ? "Overview" : page === "events" ? "Event stream" : "Detection alerts"}</strong></div>
          </div>
          <div className="topbar-actions">
            <div className={`connection-pill ${online ? "connected" : "disconnected"}`}><span className="status-dot"></span>{online ? "SYSTEM CONNECTED" : "API DISCONNECTED"}</div>
            <button className="icon-button" onClick={() => void refresh()} aria-label="Refresh data" title="Refresh data"><RefreshCw size={17} className={loading ? "spin" : ""}/></button>
            <div className="top-avatar">MR</div>
          </div>
        </header>

        <div className="content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS CONSOLE <span className="eyebrow-line"/></div>
              <h1>{page === "overview" ? "Good morning, Maureen." : page === "events" ? "Event stream" : "Detection alerts"}</h1>
              <p>{page === "overview" ? "Your security environment at a glance. Monitor activity, review detections and investigate signals." : page === "events" ? "Normalized telemetry received and stored by the AEGIS ingestion API." : "Signals raised by the current AEGIS detection rules."}</p>
            </div>
            <div className="heading-meta"><div className="date-label">{new Date().toLocaleDateString(undefined, { weekday: "long", day: "2-digit", month: "long", year: "numeric" })}</div><div className="sync-label"><span className={`status-dot ${online ? "online" : "offline"}`}/>{lastSync ? `Last sync ${lastSync.toLocaleTimeString()}` : "Awaiting connection"}</div></div>
          </div>

          {!online && <div className="notice"><div className="notice-icon"><Signal size={17}/></div><div><strong>AEGIS API is not connected</strong><span>Start the backend in your terminal with <code>uvicorn aegis.main:app --reload</code>. The console will refresh automatically.</span></div></div>}

          {page === "overview" && <>
            <div className="section-heading"><div><h2>Environment overview</h2><p>Live totals from the connected AEGIS data store</p></div><button className="subtle-button" onClick={() => void refresh()}><RefreshCw size={14}/> Refresh</button></div>
            <div className="metric-grid">
              <Metric icon={<Activity size={18}/>} label="Events ingested" value={events.length} note="Stored telemetry records" tone="teal"/>
              <Metric icon={<ShieldAlert size={18}/>} label="Detection alerts" value={alerts.length} note="Rules triggered" tone="blue"/>
              <Metric icon={<AlertOctagon size={18}/>} label="High / critical" value={highCount + criticalCount} note={`${criticalCount} critical · ${highCount} high`} tone="red"/>
              <Metric icon={<Server size={18}/>} label="API status" value={online ? "Online" : "Offline"} note={online ? "Responding normally" : "Awaiting backend"} tone={online ? "green" : "amber"} compact/>
            </div>
            <div className="overview-grid">
              <section className="panel activity-panel">
                <div className="panel-heading"><div><h3>Recent event activity</h3><p>Latest telemetry received</p></div><button className="text-button" onClick={() => setPage("events")}>View event stream <ArrowUpRight size={14}/></button></div>
                {events.length ? <div className="table-wrap"><table><thead><tr><th>EVENT</th><th>HOST</th><th>SOURCE</th><th>RECEIVED</th></tr></thead><tbody>{events.slice(0,6).map((event) => <tr key={event.event_id}><td><div className="event-title">{event.event_type.replaceAll("_"," ")}</div><div className="event-sub">{event.process_name || event.username || event.event_id.slice(0,12)}</div></td><td className="mono">{event.host}</td><td><span className="source-tag">{event.source}</span></td><td className="time-cell">{timeAgo(event.timestamp)}</td></tr>)}</tbody></table></div> : <Empty icon={<Database size={20}/>} title="No telemetry received yet" detail="Ingest a test event through the API to see activity here."/>}
              </section>
              <section className="panel severity-panel">
                <div className="panel-heading"><div><h3>Alert severity</h3><p>Current detection distribution</p></div><ShieldCheck size={18} className="panel-icon"/></div>
                <div className="severity-total"><strong>{alerts.length}</strong><span>Total alerts</span></div>
                <Severity label="Critical" count={criticalCount} total={alerts.length} tone="critical"/>
                <Severity label="High" count={highCount} total={alerts.length} tone="high"/>
                <Severity label="Medium" count={mediumCount} total={alerts.length} tone="medium"/>
                <Severity label="Low / other" count={alerts.filter(a => !["critical","high","medium"].includes(a.severity.toLowerCase())).length} total={alerts.length} tone="low"/>
                <div className="severity-foot"><span className="status-dot online"/>Detection engine reporting {online ? "through API" : "when connected"}</div>
              </section>
            </div>
            <section className="panel alerts-panel">
              <div className="panel-heading"><div><h3>Latest detections</h3><p>Review signals that require analyst attention</p></div><button className="text-button" onClick={() => setPage("alerts")}>All detections <ArrowUpRight size={14}/></button></div>
              {alerts.length ? <div className="alert-list">{alerts.slice(0,4).map(alert => <AlertRow key={alert.alert_id} alert={alert} onUpdate={updateAlert}/>)}</div> : <Empty icon={<ShieldCheck size={20}/>} title="No alerts to review" detail="Detection alerts will appear here when incoming events match an enabled rule."/>}
            </section>
          </>}

          {page !== "overview" && <section className="panel full-panel">
            <div className="panel-heading list-heading"><div><h3>{page === "events" ? "Normalized events" : "Detection queue"}</h3><p>{page === "events" ? `${events.length} records available · newest first` : `${alerts.length} alerts available · newest first`}</p></div><div className="list-tools"><div className="search-box"><Search size={15}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search records..."/>{query && <button onClick={() => setQuery("")} aria-label="Clear search"><X size={13}/></button>}</div><button className="filter-button"><ListFilter size={15}/> Filter</button></div></div>
            {page === "events" ? filteredEvents.length ? <div className="table-wrap"><table className="wide-table"><thead><tr><th>EVENT TYPE</th><th>HOST</th><th>USER</th><th>SOURCE</th><th>TIMESTAMP</th><th>EVENT ID</th></tr></thead><tbody>{filteredEvents.map(event => <tr key={event.event_id}><td><div className="event-title">{event.event_type.replaceAll("_"," ")}</div><div className="event-sub">{event.process_name || "—"}</div></td><td className="mono">{event.host}</td><td>{event.username || "—"}</td><td><span className="source-tag">{event.source}</span></td><td className="time-cell">{stamp(event.timestamp)}</td><td className="mono id-cell">{event.event_id.slice(0,12)}…</td></tr>)}</tbody></table></div> : <Empty icon={<Database size={20}/>} title="No matching events" detail="Try another search term or ingest a telemetry fixture."/> : filteredAlerts.length ? <div className="alert-list expanded">{filteredAlerts.map(alert => <AlertRow key={alert.alert_id} alert={alert} onUpdate={updateAlert}/>)}</div> : <Empty icon={<ShieldCheck size={20}/>} title="No matching alerts" detail="There are no alerts matching this search."/>}
          </section>}

          <footer className="footer"><div><span className="footer-mark"><Shield size={13}/></span> AEGIS <span className="footer-divider">·</span> Security Operations</div><div><span className={`status-dot ${online ? "online" : "offline"}`}/>{online ? "Connected to local API" : "Waiting for API"} <span className="footer-divider">·</span> v0.1.0</div></footer>
        </div>
      </main>
    </div>
  );
}

function Metric({ icon, label, value, note, tone, compact = false }: { icon: ReactNode; label: string; value: string | number; note: string; tone: string; compact?: boolean }) {
  return <div className="metric-card"><div className="metric-top"><span className={`metric-icon ${tone}`}>{icon}</span><span className="metric-label">{label}</span><span className="metric-trend"><ArrowDownRight size={13}/></span></div><div className={`metric-value ${compact ? "compact-value" : ""}`}>{value}</div><div className="metric-note">{note}</div></div>;
}
function Severity({ label, count, total, tone }: { label: string; count: number; total: number; tone: string }) {
  return <div className="severity-row"><div className="severity-label"><span className={`severity-dot ${tone}`}/>{label}<strong>{count}</strong></div><div className="severity-track"><span className={tone} style={{ width: `${total ? count / total * 100 : 0}%` }}/></div></div>;
}
function AlertRow({ alert, onUpdate }: { alert: AlertRecord; onUpdate: (id: string, status: AlertRecord["status"], note: string) => Promise<void> }) {
  const [note, setNote] = useState(alert.analyst_note || "");
  const [status, setStatus] = useState<AlertRecord["status"]>(alert.status || "new");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const save = async () => {
    setSaving(true); setError("");
    try { await onUpdate(alert.alert_id, status, note); }
    catch { setError("Update failed. Check the API connection and try again."); }
    finally { setSaving(false); }
  };
  return <div className="alert-row"><div className={`alert-symbol ${alert.severity.toLowerCase()}`}><ShieldAlert size={17}/></div><div className="alert-main"><div className="alert-title-line"><strong>{alert.title}</strong><span className={`severity-badge ${alert.severity.toLowerCase()}`}>{alert.severity}</span><span className={`triage-badge ${status}`}>{status.replace("_", " ")}</span></div><p>{alert.description}</p><div className="alert-meta"><span>{alert.rule_id}</span><span>{alert.mitre_techniques?.join(", ") || "ATT&CK mapping pending"}</span><span>{alert.event_ids?.length || 0} evidence event(s)</span></div><div className="triage-controls"><label>Analyst status<select value={status} onChange={e => setStatus(e.target.value as AlertRecord["status"])}><option value="new">New</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option></select></label><label className="note-field">Investigation note<textarea value={note} maxLength={2000} onChange={e => setNote(e.target.value)} placeholder="Record what you reviewed, evidence observed, and next steps..."/></label><button className="save-triage" onClick={() => void save()} disabled={saving}>{saving ? "Saving..." : "Save triage"}</button>{error && <span className="triage-error">{error}</span>}</div></div><div className="alert-time"><Clock3 size={13}/>{timeAgo(alert.created_at)}</div></div>;
}
function Empty({ icon, title, detail }: { icon: React.ReactNode; title: string; detail: string }) {
  return <div className="empty-state"><div className="empty-icon">{icon}</div><strong>{title}</strong><span>{detail}</span></div>;
}
export default App;