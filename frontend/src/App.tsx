import {
  useCallback,
  useEffect,
  useState,
} from "react";

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


const API_BASE_URL =
  "http://127.0.0.1:8000";


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


type HealthStatus = {
  status: string;
  full_model_loaded: boolean;
  live_model_loaded: boolean;
  full_model: string;
  live_model: string;
  live_algorithm: string;
  full_model_threshold: number;
  live_anomaly_threshold: number;
  live_threshold_percentile: number;
  number_of_features: number;
  live_number_of_features: number;
};


function App() {

  const [
    statistics,
    setStatistics,
  ] = useState<Statistics | null>(
    null
  );

  const [
    events,
    setEvents,
  ] = useState<SecurityEvent[]>([]);

  const [
    alerts,
    setAlerts,
  ] = useState<Alert[]>([]);

  const [
    severityAnalytics,
    setSeverityAnalytics,
  ] = useState<AnalyticsData>({});

  const [
    protocolAnalytics,
    setProtocolAnalytics,
  ] = useState<AnalyticsData>({});

  const [
    health,
    setHealth,
  ] = useState<HealthStatus | null>(
    null
  );

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState("");

  const [
    lastUpdated,
    setLastUpdated,
  ] = useState<Date | null>(
    null
  );


  const loadData =
    useCallback(
      async () => {

        try {

          setError("");

          const [
            statisticsResponse,
            eventsResponse,
            alertsResponse,
            severityResponse,
            protocolResponse,
            healthResponse,
          ] = await Promise.all([

            fetch(
              `${API_BASE_URL}/statistics`
            ),

            fetch(
              `${API_BASE_URL}/events?limit=20`
            ),

            fetch(
              `${API_BASE_URL}/alerts?limit=10`
            ),

            fetch(
              `${API_BASE_URL}/analytics/severity`
            ),

            fetch(
              `${API_BASE_URL}/analytics/protocols`
            ),

            fetch(
              `${API_BASE_URL}/health`
            ),
          ]);


          if (
            !statisticsResponse.ok ||
            !eventsResponse.ok ||
            !alertsResponse.ok ||
            !severityResponse.ok ||
            !protocolResponse.ok ||
            !healthResponse.ok
          ) {

            throw new Error(
              "Failed to load backend data."
            );
          }


          const statisticsData:
            Statistics =
              await statisticsResponse.json();

          const eventsData:
            SecurityEvent[] =
              await eventsResponse.json();

          const alertsData:
            Alert[] =
              await alertsResponse.json();

          const severityData:
            AnalyticsData =
              await severityResponse.json();

          const protocolData:
            AnalyticsData =
              await protocolResponse.json();

          const healthData:
            HealthStatus =
              await healthResponse.json();


          setStatistics(
            statisticsData
          );

          setEvents(
            eventsData
          );

          setAlerts(
            alertsData
          );

          setSeverityAnalytics(
            severityData
          );

          setProtocolAnalytics(
            protocolData
          );

          setHealth(
            healthData
          );

          setLastUpdated(
            new Date()
          );

        } catch (err) {

          console.error(err);

          setError(
            "Could not connect to the FastAPI backend."
          );

        } finally {

          setLoading(false);
        }
      },
      []
    );


  useEffect(() => {

    loadData();

    const interval =
      window.setInterval(
        () => {
          loadData();
        },
        5000
      );

    return () => {
      window.clearInterval(
        interval
      );
    };

  }, [loadData]);


  const severityClass = (
    severity: string
  ) => {

    return (
      `severity severity-${severity.toLowerCase()}`
    );
  };


  const predictionClass = (
    prediction: string
  ) => {

    return prediction === "ATTACK"

      ? "prediction prediction-anomaly"

      : "prediction prediction-normal";
  };


  const displayPrediction = (
    prediction: string
  ) => {

    return prediction === "ATTACK"
      ? "ANOMALY"
      : "NORMAL";
  };


  const formatDate = (
    timestamp: string
  ) => {

    return new Date(
      timestamp
    ).toLocaleString();
  };


  const formatBytes = (
    bytes: number | null
  ) => {

    if (
      bytes === null ||
      bytes === undefined
    ) {
      return "N/A";
    }

    if (bytes < 1024) {
      return `${bytes} B`;
    }

    if (
      bytes < 1024 * 1024
    ) {

      return (
        `${(
          bytes / 1024
        ).toFixed(1)} KB`
      );
    }

    return (
      `${(
        bytes /
        (1024 * 1024)
      ).toFixed(1)} MB`
    );
  };


  const severityChartData =
    Object.entries(
      severityAnalytics
    ).map(
      ([name, value]) => ({
        name,
        value,
      })
    );


  const protocolChartData =
    Object.entries(
      protocolAnalytics
    ).map(
      ([name, value]) => ({
        name,
        value,
      })
    );


  const severityColors:
    Record<string, string> = {

      LOW: "#24d18a",
      MEDIUM: "#ffd76a",
      HIGH: "#ffad54",
      CRITICAL: "#ff6262",
    };


  const totalEvents =
    statistics?.total_events ?? 0;

  const normalEvents =
    statistics?.normal_events ?? 0;

  const anomalyEvents =
    statistics?.attack_events ?? 0;


  const normalPercent =
    totalEvents > 0

      ? (
          normalEvents /
          totalEvents
        ) * 100

      : 0;


  const anomalyPercent =
    totalEvents > 0

      ? (
          anomalyEvents /
          totalEvents
        ) * 100

      : 0;


  if (loading) {

    return (

      <div className="center-screen">

        <div className="loader">
        </div>

        <p>
          Loading security data...
        </p>

      </div>
    );
  }


  return (

    <div className="dashboard">

      <header className="topbar">

        <div>

          <p className="eyebrow">
            REAL-TIME NETWORK ANOMALY DETECTION
          </p>

          <h1>
            AI Cybersecurity Platform
          </h1>

          <p className="subtitle">
            Live network monitoring powered by
            One-Class SVM anomaly detection
          </p>

        </div>


        <div className="topbar-right">

          <div className="system-status">

            <span className="status-dot">
            </span>

            System Online

          </div>


          <div className="model-badge">

            <span>
              AI Engine
            </span>

            <strong>
              {health?.live_algorithm ??
                "OneClassSVM"}
            </strong>

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

        <section className="engine-banner">

          <div>

            <span className="engine-label">
              LIVE DETECTION ENGINE
            </span>

            <strong>
              {health?.live_model ??
                "Live Network Anomaly Detector V3"}
            </strong>

          </div>


          <div className="engine-details">

            <span>
              Algorithm:
              {" "}
              <strong>
                {health?.live_algorithm ??
                  "OneClassSVM"}
              </strong>
            </span>

            <span>
              Features:
              {" "}
              <strong>
                {health?.live_number_of_features ??
                  11}
              </strong>
            </span>

            <span>
              Calibration:
              {" "}
              <strong>
                {health
                  ? `${(
                      health.live_threshold_percentile *
                      100
                    ).toFixed(1)}th percentile`
                  : "97.5th percentile"}
              </strong>
            </span>

          </div>

        </section>


        <section className="stats-grid">

          <div className="stat-card">

            <p>
              Total Events
            </p>

            <h2>
              {totalEvents}
            </h2>

            <span>
              Network flows analyzed
            </span>

          </div>


          <div className="stat-card normal-card">

            <p>
              Normal Traffic
            </p>

            <h2>
              {normalEvents}
            </h2>

            <span>
              Flows classified as normal
            </span>

          </div>


          <div className="stat-card anomaly-card">

            <p>
              Detected Anomalies
            </p>

            <h2>
              {anomalyEvents}
            </h2>

            <span>
              Unusual network behavior
            </span>

          </div>


          <div className="stat-card critical-card">

            <p>
              Critical Alerts
            </p>

            <h2>
              {statistics?.critical_events ?? 0}
            </h2>

            <span>
              Highest-risk events
            </span>

          </div>


          <div className="stat-card risk-card">

            <p>
              Average Risk
            </p>

            <h2>
              {statistics
                ?.average_risk_score
                ?.toFixed(2) ??
                "0.00"}
            </h2>

            <span>
              Anomaly risk score
            </span>

          </div>

        </section>


        <section className="overview-grid">

          <div className="panel">

            <div className="panel-header">

              <div>

                <p className="panel-kicker">
                  LIVE TRAFFIC OVERVIEW
                </p>

                <h3>
                  Normal vs Anomaly
                </h3>

              </div>


              <span className="count-badge">
                {totalEvents} flows
              </span>

            </div>


            <div className="traffic-summary">

              <div className="traffic-row">

                <div>

                  <span className="legend-dot normal-dot">
                  </span>

                  Normal Traffic

                </div>

                <strong>
                  {normalEvents}
                  {" "}
                  ({normalPercent.toFixed(1)}%)
                </strong>

              </div>


              <div className="progress-track">

                <div
                  className="progress-bar normal-progress"
                  style={{
                    width:
                      `${normalPercent}%`,
                  }}
                >
                </div>

              </div>


              <div className="traffic-row anomaly-row">

                <div>

                  <span className="legend-dot anomaly-dot">
                  </span>

                  Anomalous Traffic

                </div>

                <strong>
                  {anomalyEvents}
                  {" "}
                  ({anomalyPercent.toFixed(1)}%)
                </strong>

              </div>


              <div className="progress-track">

                <div
                  className="progress-bar anomaly-progress"
                  style={{
                    width:
                      `${anomalyPercent}%`,
                  }}
                >
                </div>

              </div>

            </div>

          </div>


          <div className="panel risk-panel">

            <p className="panel-kicker">
              AI ANOMALY RISK
            </p>

            <h3>
              Average Risk Level
            </h3>


            <div className="risk-circle">

              <span>
                {statistics
                  ?.average_risk_score
                  ?.toFixed(0) ??
                  0}
              </span>

              <small>
                /100
              </small>

            </div>


            <p className="risk-description">
              Higher values indicate network
              behavior further from the learned
              normal baseline.
            </p>


            <div className="threshold-info">

              <span>
                Live Threshold
              </span>

              <strong>
                {health
                  ?.live_anomaly_threshold
                  ?.toFixed(4) ??
                  "N/A"}
              </strong>

            </div>

          </div>

        </section>


        <section className="analytics-grid">

          <div className="panel analytics-panel">

            <div className="panel-header">

              <div>

                <p className="panel-kicker">
                  RISK ANALYTICS
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
                            ] ||
                            "#5ab6ff"
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
                ANOMALY MONITORING
              </p>

              <h3>
                Recent Anomaly Alerts
              </h3>

            </div>

            <span className="count-badge">
              {alerts.length} recent
            </span>

          </div>


          {alerts.length === 0 ? (

            <p className="empty-state">
              No network anomalies detected.
            </p>

          ) : (

            <div className="alerts-list">

              {alerts.map(
                (alert) => (

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
                          Network Anomaly Detected
                        </strong>

                        <span
                          className={
                            severityClass(
                              alert.severity
                            )
                          }
                        >
                          {alert.severity}
                        </span>

                      </div>


                      <div className="alert-details">

                        <span>
                          Protocol:
                          {" "}
                          {alert.protocol ||
                            "N/A"}
                        </span>

                        <span>
                          Detector:
                          {" "}
                          One-Class SVM V3
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
                        {alert.risk_score
                          .toFixed(0)}
                      </span>

                      <small>
                        Risk
                      </small>

                    </div>

                  </div>
                )
              )}

            </div>
          )}

        </section>


        <section className="panel">

          <div className="panel-header">

            <div>

              <p className="panel-kicker">
                LIVE NETWORK ACTIVITY
              </p>

              <h3>
                Recent Network Events
              </h3>

            </div>

            <span className="count-badge">
              Auto-refresh 5s
            </span>

          </div>


          <div className="table-wrapper">

            <table>

              <thead>

                <tr>

                  <th>
                    ID
                  </th>

                  <th>
                    Time
                  </th>

                  <th>
                    Protocol
                  </th>

                  <th>
                    Duration
                  </th>

                  <th>
                    Source Bytes
                  </th>

                  <th>
                    Destination Bytes
                  </th>

                  <th>
                    Risk
                  </th>

                  <th>
                    Severity
                  </th>

                  <th>
                    Classification
                  </th>

                </tr>

              </thead>


              <tbody>

                {events.map(
                  (event) => (

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
                        {event.duration !== null
                          ? `${event.duration.toFixed(
                              3
                            )}s`
                          : "N/A"}
                      </td>

                      <td>
                        {formatBytes(
                          event.source_bytes
                        )}
                      </td>

                      <td>
                        {formatBytes(
                          event.destination_bytes
                        )}
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
                          className={
                            severityClass(
                              event.severity
                            )
                          }
                        >
                          {event.severity}
                        </span>

                      </td>

                      <td>

                        <span
                          className={
                            predictionClass(
                              event.prediction
                            )
                          }
                        >
                          {displayPrediction(
                            event.prediction
                          )}
                        </span>

                      </td>

                    </tr>
                  )
                )}

              </tbody>

            </table>

          </div>

        </section>

      </main>


      <footer>

        <span>
          AI Cybersecurity Platform •
          Live Anomaly Detection V3
        </span>

        <span>
          Last updated:
          {" "}
          {lastUpdated
            ? lastUpdated
                .toLocaleTimeString()
            : "N/A"}
        </span>

      </footer>

    </div>
  );
}


export default App;
