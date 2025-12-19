import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import {
  Shield,
  Globe,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
} from "lucide-react";

interface Rule {
  SecurityGroupName: string;
  SecurityGroupId: string;
  Protocol: string;
  PortRange: string;
  OpenTo: string;
  Risk: string;
}

export default function Index() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);

  const fetchData = async () => {
    const res = await fetch(
      "http://localhost:8000/backend/data/security_analysis.json"
    );
    const data = await res.json();
    setRules(data);
  };

  const runScan = async () => {
    setLoading(true);
    await fetch("http://localhost:8000/api/scan");
    await fetchData();
    setLoading(false);
  };

  useEffect(() => {
    fetchData();
  }, []);

  const totalPublic = rules.length;
  const allowed = rules.filter((r) => r.Risk.includes("ALLOWED")).length;
  const highRisk = rules.filter((r) => r.Risk.includes("HIGH")).length;
  const securityGroups = new Set(
    rules.map((r) => r.SecurityGroupId)
  ).size;

  const filteredRules = rules.filter(
    (r) =>
      r.SecurityGroupName.toLowerCase().includes(search.toLowerCase()) ||
      r.SecurityGroupId.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="flex min-h-screen bg-muted/40">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 text-white p-6">
        <div className="flex items-center gap-2 text-xl font-bold mb-8">
          <Shield className="h-6 w-6 text-blue-400" />
          SecurityHub
        </div>

        <nav className="space-y-2">
          <div className="rounded-md bg-blue-600 px-4 py-2">
            Dashboard
          </div>
          <div className="px-4 py-2 text-slate-300">Reports</div>
        </nav>

        <div className="mt-auto pt-10 text-xs text-slate-400">
          LAST SCAN
          <div className="text-white mt-1">
            {new Date().toLocaleString()}
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 p-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <h1 className="text-3xl font-bold">
            AWS Security Group Risk Dashboard
          </h1>

          <Button onClick={runScan} disabled={loading}>
            <RefreshCw className="mr-2 h-4 w-4" />
            {loading ? "Scanning..." : "Refresh Data"}
          </Button>
        </div>

        {/* Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10">
          <MetricCard
            icon={<Shield />}
            value={securityGroups}
            label="Security Groups Scanned"
          />
          <MetricCard
            icon={<Globe />}
            value={totalPublic}
            label="Total Public Rules"
            color="yellow"
          />
          <MetricCard
            icon={<CheckCircle2 />}
            value={allowed}
            label="Allowed Rules (80/443)"
            color="green"
          />
          <MetricCard
            icon={<AlertTriangle />}
            value={highRisk}
            label="High Risk Rules"
            color="red"
            danger
          />
        </div>

        {/* Table */}
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold">
                Public Security Group Rules
              </h2>

              <div className="relative w-64">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search rules..."
                  className="pl-8"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
            </div>

            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>SECURITY GROUP NAME</TableHead>
                  <TableHead>SECURITY GROUP ID</TableHead>
                  <TableHead>PROTOCOL</TableHead>
                  <TableHead>PORT RANGE</TableHead>
                  <TableHead>OPEN TO</TableHead>
                  <TableHead>RISK LEVEL</TableHead>
                </TableRow>
              </TableHeader>

              <TableBody>
                {filteredRules.map((rule, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-medium">
                      {rule.SecurityGroupName}
                    </TableCell>
                    <TableCell>{rule.SecurityGroupId}</TableCell>
                    <TableCell>{rule.Protocol}</TableCell>
                    <TableCell>{rule.PortRange}</TableCell>
                    <TableCell>{rule.OpenTo}</TableCell>
                    <TableCell>
                      <span
                        className={`rounded-full px-3 py-1 text-xs font-semibold ${
                          rule.Risk.includes("HIGH")
                            ? "bg-red-100 text-red-600"
                            : "bg-green-100 text-green-600"
                        }`}
                      >
                        {rule.Risk}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}

                {filteredRules.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center">
                      No public rules found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}

/* ---------- Metric Card Component ---------- */
function MetricCard({
  icon,
  value,
  label,
  color = "blue",
  danger = false,
}: any) {
  const colors: any = {
    blue: "bg-blue-100 text-blue-600",
    green: "bg-green-100 text-green-600",
    yellow: "bg-yellow-100 text-yellow-600",
    red: "bg-red-100 text-red-600",
  };

  return (
    <Card className={danger ? "border-red-300" : ""}>
      <CardContent className="p-6 flex items-center gap-4">
        <div className={`p-3 rounded-lg ${colors[color]}`}>
          {icon}
        </div>
        <div>
          <div className="text-3xl font-bold">{value}</div>
          <div className="text-sm text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}
