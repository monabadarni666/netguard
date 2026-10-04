import { useCallback, useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";

import "./App.css";

const API_BASE_URL = "http://127.0.0.1:8000";

type Statistics = {
  total_events: number;
  attack_events: number;
  normal_events: number;
  critical_events: number;
  average_risk_score: number;
};

type SecurityEvent = {
  id: number;
  timestamp: string;
  prediction: string;
  risk_score: number;
  severity: string;
  protocol: string | null;
  service: string | null;
  state: string | null;
  duration: number | null;
  source_bytes: number | null;
  destination_bytes: number | null;
};

type Alert = {
  id: number;
  timestamp: string;
  risk_score: number;
  severity: string;
  protocol: string | null;
  service: string | null;
  state: string | null;
};

type AnalyticsData = {
  [key: string]: number;
};

function App() {
  const [statistics, setStatistics] = useState<Statistics | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);

  const [severityAnalytics, setSeverityAnalytics] =
    useState<AnalyticsData>({});

  const [protocolAnalytics, setProtocolAnalytics] =
    useState<AnalyticsData>({});

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [lastUpdated, setLastUpdated] =
    useState<Date | null>(null);

  const loadData = useCallback(async () => {
    try {
      setError("");

      const [
        statisticsResponse,
        eventsResponse,
        alertsResponse,
        severityResponse,
        protocolResponse,
      ] = await Promise.all([
        fetch(`${API_BASE_URL}/statistics`),
        fetch(`${API_BASE_URL}/events?limit=20`),
        fetch(`${API_BASE_URL}/alerts?limit=10`),
        fetch(`${API_BASE_URL}/analytics/severity`),
        fetch(`${API_BASE_URL}/analytics/protocols`),
      ]);

      if (
        !statisticsResponse.ok ||
        !eventsResponse.ok ||
        !alertsResponse.ok ||
        !severityResponse.ok ||
        !protocolResponse.ok
      ) {
        throw new Error("Failed to load backend data.");
      }

      const statisticsData: Statistics =
        await statisticsResponse.json();

      const eventsData: SecurityEvent[] =
        await eventsResponse.json();

      const alertsData: Alert[] =
        await alertsResponse.json();

      const severityData: AnalyticsData =
        await severityResponse.json();

      const protocolData: AnalyticsData =
        await protocolResponse.json();

      setStatistics(statisticsData);
      setEvents(eventsData);
      setAlerts(alertsData);
      setSeverityAnalytics(severityData);
      setProtocolAnalytics(protocolData);

      setLastUpdated(new Date());
    } catch (err) {
      console.error(err);

      setError(
        "Could not connect to the FastAPI backend."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();

    const interval = window.setInterval(() => {
      loadData();
    }, 5000);

    return () => {
      window.clearInterval(interval);
    };
  }, [loadData]);

  const severityClass = (severity: string) => {
    return `severity severity-${severity.toLowerCase()}`;
  };

  const predictionClass = (prediction: string) => {
    return prediction === "ATTACK"
      ? "prediction prediction-attack"
      : "prediction prediction-normal";
  };

  const formatDate = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const severityChartData = Object.entries(
    severityAnalytics
  ).map(([name, value]) => ({
    name,
    value,
  }));

  const protocolChartData = Object.entries(
    protocolAnalytics
  ).map(([name, value]) => ({
    name,
    value,
  }));

  const severityColors: Record<string, string> = {
    LOW: "#24d18a",
    MEDIUM: "#ffd76a",
    HIGH: "#ffad54",
    CRITICAL: "#ff6262",
  };

  if (loading) {
    return (
      <div className="center-screen">
        <div className="loader"></div>
        <p>Loading security data...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="topbar">
        <div>
          <p className="eyebrow">
            NETWORK INTRUSION DETECTION
          </p>

          <h1>AI Cybersecurity Platform</h1>

          <p className="subtitle">
            Machine-learning powered network security monitoring
          </p>
        </div>

        <div className="topbar-right">
          <div className="system-status">
            <span className="status-dot"></span>
            System Online
          </div>

          <button
            onClick={loadData}
            className="refresh-button"
          >
            Refresh
          </button>
        </div>
      </header>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      <main>
        <section className="stats-grid">
          <div className="stat-card">
            <p>Total Events</p>

            <h2>
              {statistics?.total_events ?? 0}
            </h2>

            <span>
              Network flows analyzed
            </span>
          </div>

          <div className="stat-card attack-card">
            <p>Detected Attacks</p>

            <h2>
              {statistics?.attack_events ?? 0}
            </h2>

            <span>
              Threats identified by AI
            </span>
          </div>

          <div className="stat-card critical-card">
            <p>Critical Alerts</p>

            <h2>
              {statistics?.critical_events ?? 0}
            </h2>

            <span>
              Highest risk events
            </span>
          </div>

          <div className="stat-card">
            <p>Average Risk Score</p>

            <h2>
              {statistics?.average_risk_score?.toFixed(2) ??
                "0.00"}
            </h2>

            <span>
              Average AI risk level
            </span>
          </div>
        </section>

        <section className="overview-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <p className="panel-kicker">
                  TRAFFIC OVERVIEW
                </p>

                <h3>
                  Normal vs Attack
                </h3>
              </div>
            </div>

            <div className="traffic-summary">
              <div className="traffic-row">
                <div>
                  <span className="legend-dot normal-dot"></span>
                  Normal Traffic
                </div>

                <strong>
                  {statistics?.normal_events ?? 0}
                </strong>
              </div>

              <div className="progress-track">
                <div
                  className="progress-bar normal-progress"
                  style={{
                    width: `${
                      statistics?.total_events
                        ? (
                            statistics.normal_events /
                            statistics.total_events
                          ) * 100
                        : 0
                    }%`,
                  }}
                ></div>
              </div>

              <div className="traffic-row attack-row">
                <div>
                  <span className="legend-dot attack-dot"></span>
                  Attack Traffic
                </div>

                <strong>
                  {statistics?.attack_events ?? 0}
                </strong>
              </div>

              <div className="progress-track">
                <div
                  className="progress-bar attack-progress"
                  style={{
                    width: `${
                      statistics?.total_events
                        ? (
                            statistics.attack_events /
                            statistics.total_events
                          ) * 100
                        : 0
                    }%`,
                  }}
                ></div>
              </div>
            </div>
          </div>

          <div className="panel risk-panel">
            <p className="panel-kicker">
              AI RISK ENGINE
            </p>

            <h3>
              Current Risk Level
            </h3>

            <div className="risk-circle">
              <span>
                {statistics?.average_risk_score?.toFixed(0) ??
                  0}
              </span>

              <small>
                /100
              </small>
            </div>

            <p className="risk-description">
              Calculated from stored network security events.
            </p>
          </div>
        </section>

        <section className="analytics-grid">
          <div className="panel analytics-panel">
            <div className="panel-header">
              <div>
                <p className="panel-kicker">
                  THREAT ANALYTICS
                </p>

                <h3>
                  Severity Distribution
                </h3>
              </div>
            </div>

            <div className="chart-container">
              <ResponsiveContainer
                width="100%"
                height={300}
              >
                <PieChart>
                  <Pie
                    data={severityChartData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={70}
                    outerRadius={110}
                    paddingAngle={3}
                  >
                    {severityChartData.map(
                      (entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={
                            severityColors[
                              entry.name
                            ] || "#5ab6ff"
                          }
                        />
                      )
                    )}
                  </Pie>

                  <Tooltip />

                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="panel analytics-panel">
            <div className="panel-header">
              <div>
                <p className="panel-kicker">
                  NETWORK ANALYTICS
                </p>

                <h3>
                  Protocol Distribution
                </h3>
              </div>
            </div>

            <div className="chart-container">
              <ResponsiveContainer
                width="100%"
                height={300}
              >
                <BarChart
                  data={protocolChartData}
                >
                  <XAxis
                    dataKey="name"
                    stroke="#71879f"
                  />

                  <YAxis
                    stroke="#71879f"
                  />

                  <Tooltip />

                  <Bar
                    dataKey="value"
                    fill="#5ab6ff"
                    radius={[6, 6, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        <section className="panel alerts-panel">
          <div className="panel-header">
            <div>
              <p className="panel-kicker">
                SECURITY MONITORING
              </p>

              <h3>
                Recent Security Alerts
              </h3>
            </div>

            <span className="count-badge">
              {alerts.length} recent
            </span>
          </div>

          {alerts.length === 0 ? (
            <p className="empty-state">
              No security alerts detected.
            </p>
          ) : (
            <div className="alerts-list">
              {alerts.map((alert) => (
                <div
                  className="alert-item"
                  key={alert.id}
                >
                  <div className="alert-icon">
                    !
                  </div>

                  <div className="alert-main">
                    <div className="alert-title-row">
                      <strong>
                        Potential Network Attack
                      </strong>

                      <span
                        className={severityClass(
                          alert.severity
                        )}
                      >
                        {alert.severity}
                      </span>
                    </div>

                    <div className="alert-details">
                      <span>
                        Protocol:{" "}
                        {alert.protocol || "N/A"}
                      </span>

                      <span>
                        Service:{" "}
                        {alert.service || "N/A"}
                      </span>

                      <span>
                        State:{" "}
                        {alert.state || "N/A"}
                      </span>
                    </div>

                    <small>
                      {formatDate(
                        alert.timestamp
                      )}
                    </small>
                  </div>

                  <div className="risk-number">
                    <span>
                      {alert.risk_score.toFixed(0)}
                    </span>

                    <small>
                      Risk
                    </small>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="panel-kicker">
                NETWORK ACTIVITY
              </p>

              <h3>
                Recent Events
              </h3>
            </div>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Time</th>
                  <th>Protocol</th>
                  <th>Service</th>
                  <th>State</th>
                  <th>Risk</th>
                  <th>Severity</th>
                  <th>Prediction</th>
                </tr>
              </thead>

              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td>
                      #{event.id}
                    </td>

                    <td>
                      {formatDate(
                        event.timestamp
                      )}
                    </td>

                    <td>
                      {event.protocol ||
                        "N/A"}
                    </td>

                    <td>
                      {event.service ||
                        "N/A"}
                    </td>

                    <td>
                      {event.state ||
                        "N/A"}
                    </td>

                    <td>
                      <strong>
                        {event.risk_score.toFixed(
                          2
                        )}
                      </strong>
                    </td>

                    <td>
                      <span
                        className={severityClass(
                          event.severity
                        )}
                      >
                        {event.severity}
                      </span>
                    </td>

                    <td>
                      <span
                        className={predictionClass(
                          event.prediction
                        )}
                      >
                        {event.prediction}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      <footer>
        <span>
          AI Cybersecurity Platform
        </span>

        <span>
          Last updated:{" "}
          {lastUpdated
            ? lastUpdated.toLocaleTimeString()
            : "N/A"}
        </span>
      </footer>
    </div>
  );
}

export default App;
