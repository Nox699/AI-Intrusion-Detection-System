/* Private network charts: no IPs and never 65,535 individual port bars. */
"use strict";
(() => {
  const activity = document.getElementById("network-activity-chart");
  const ports = document.getElementById("network-ports-chart");
  if (!activity || !ports) return;

  const hours = Math.min(720, Math.max(1, Number(activity.dataset.hours) || 24));
  const numbers = new Intl.NumberFormat("da-DK");
  const font = { family: '"Segoe UI",Arial,sans-serif', color: "#8797ad", size: 11 };

  function failure(message) {
    for (const box of [activity, ports]) {
      const warning = document.createElement("p");
      warning.className = "chart-loading";
      warning.textContent = message;
      box.replaceChildren(warning);
    }
  }

  async function show() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch("/api/network-charts?hours=" + hours, {
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
        headers: { Accept: "application/json" }
      });
      if (response.status === 401) throw new Error("Log ind igen for at se graferne.");
      if (!response.ok) throw new Error("Netværkshistorikken kunne ikke læses.");
      if (!window.Plotly) throw new Error("Det lokale grafbibliotek kunne ikke indlæses.");

      const data = (await response.json()).data;
      const rows = Array.isArray(data.series) ? data.series.filter(
        row => Number.isFinite(row.timestamp) && Number.isSafeInteger(row.packets) &&
          row.packets > 0
      ).slice(0, 360) : [];
      const visible = Array.isArray(data.top_ports) ? data.top_ports.filter(
        row => Number.isInteger(row.port) && row.port >= 0 && row.port <= 65535 &&
          Number.isSafeInteger(row.packets) && row.packets > 0
      ).slice(0, 10) : [];
      const other = Number.isSafeInteger(data.other_ports_packets) &&
        data.other_ports_packets > 0 ? data.other_ports_packets : 0;
      const base = {
        paper_bgcolor: "transparent", plot_bgcolor: "transparent", font,
        margin: { l: 55, r: 22, t: 14, b: 50 }, showlegend: false,
        dragmode: false, hovermode: "closest",
        xaxis: { gridcolor: "#233040", zeroline: false, fixedrange: true },
        yaxis: { gridcolor: "#233040", zeroline: false, fixedrange: true },
        hoverlabel: {
          bgcolor: "#1b293b", bordercolor: "#3a526b",
          font: { color: "#e1ebf6" }
        }
      };
      const settings = { responsive: true, displayModeBar: false, scrollZoom: false };

      const activityTrace = {
        type: "bar",
        x: rows.map(row => new Date(row.timestamp * 1000).toISOString()),
        y: rows.map(row => row.packets),
        width: Math.max(60000, Number(data.bucket_seconds) * 1000 * 0.75),
        marker: { color: "#3cbbb1" },
        hovertemplate: "%{x}<br>%{y} loggede SYN-pakker<extra></extra>"
      };
      const activityLayout = {
        ...base,
        // Empty Plotly date axes otherwise default to misleading dates around year 2000.
        xaxis: { ...base.xaxis, type: "date", visible: rows.length > 0 },
        yaxis: { ...base.yaxis, rangemode: "tozero", tickformat: ",d", dtick: 1,
          visible: rows.length > 0 },
        annotations: rows.length ? [] : [{
          x: 0.5, y: 0.5, xref: "paper", yref: "paper",
          text: "Ingen loggede blokerede SYN-pakker i perioden",
          font: { color: "#8797ad" }, showarrow: false
        }]
      };
      await window.Plotly.newPlot(activity, [activityTrace], activityLayout, settings);

      const labels = visible.map(row => "Port " + row.port);
      const counts = visible.map(row => row.packets);
      if (other > 0) {
        labels.push("Øvrige porte");
        counts.push(other);
      }
      const portTrace = {
        type: "bar", orientation: "h",
        x: [...counts].reverse(), y: [...labels].reverse(),
        marker: {
          color: [...labels].reverse().map(label =>
            label === "Øvrige porte" ? "#8894a8" : "#6485a8")
        },
        hovertemplate: "%{y}: %{x} loggede SYN-pakker<extra></extra>"
      };
      const portLayout = {
        ...base,
        margin: { l: 110, r: 22, t: 14, b: 42 },
        xaxis: { ...base.xaxis, rangemode: "tozero", tickformat: ",d", dtick: 1,
          visible: labels.length > 0 },
        yaxis: { type: "category", fixedrange: true, automargin: true,
          visible: labels.length > 0 },
        annotations: labels.length ? [] : [{
          x: 0.5, y: 0.5, xref: "paper", yref: "paper",
          text: "Ingen porte registreret i perioden",
          font: { color: "#8797ad" }, showarrow: false
        }]
      };
      await window.Plotly.newPlot(ports, [portTrace], portLayout, settings);
      activity.setAttribute(
        "aria-label",
        "Blokerede TCP SYN-pakker pr. interval, samlet " +
          numbers.format(data.total_packets) + " poster"
      );
      ports.setAttribute(
        "aria-label",
        "Højst ti destinationporte og Øvrige porte. " +
          numbers.format(data.unique_ports) + " forskellige porte registreret"
      );
    } catch (problem) {
      failure(problem.name === "AbortError"
        ? "Grafens data tog for lang tid at hente."
        : problem.message);
    } finally {
      clearTimeout(timeout);
    }
  }
  show();
})();
