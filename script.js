async function loadData() {
  const res = await fetch("/backend/data/security_analysis.json");
  const data = await res.json();

  const table = document.getElementById("table-body");
  table.innerHTML = "";

  data.forEach(rule => {
    const row = document.createElement("tr");

    row.innerHTML = `
      <td>${rule.SecurityGroupName}</td>
      <td>${rule.PortRange}</td>
      <td>${rule.Protocol}</td>
      <td>${rule.OpenTo}</td>
      <td class="${rule.Risk.includes("HIGH") ? "risk" : "allowed"}">
        ${rule.Risk}
      </td>
    `;

    table.appendChild(row);
  });
}

async function runScan() {
  await fetch("/api/scan");
  loadData();
}

loadData();
setInterval(loadData, 30000); // auto refresh every 30 sec
