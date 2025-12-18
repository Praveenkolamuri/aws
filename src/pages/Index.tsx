import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

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
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    const res = await fetch(
      "http://localhost:8000/backend/data/security_analysis.json"
    );
    const data = await res.json();
    setRules(data);
  };

  const runScan = async () => {
    setLoading(true);
    await fetch("http://localhost:8000/api/scan");
    await loadData();
    setLoading(false);
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="min-h-screen bg-background p-8">
      {/* Page Title */}
      <h1 className="mb-6 text-3xl font-bold">
        AWS Security Group Risk Dashboard
      </h1>

      {/* Action */}
      <Button onClick={runScan} disabled={loading} className="mb-6">
        {loading ? "Scanning..." : "Run Security Scan"}
      </Button>

      {/* Table Card */}
      <Card>
        <CardHeader>
          <CardTitle>Public Security Group Rules</CardTitle>
        </CardHeader>

        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Security Group</TableHead>
                <TableHead>Port</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Open To</TableHead>
                <TableHead>Risk</TableHead>
              </TableRow>
            </TableHeader>

            <TableBody>
              {rules.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="text-center text-muted-foreground"
                  >
                    No public rules found
                  </TableCell>
                </TableRow>
              )}

              {rules.map((rule, index) => (
                <TableRow key={index}>
                  <TableCell>{rule.SecurityGroupName}</TableCell>
                  <TableCell>{rule.PortRange}</TableCell>
                  <TableCell>{rule.Protocol}</TableCell>
                  <TableCell>{rule.OpenTo}</TableCell>
                  <TableCell
                    className={
                      rule.Risk.includes("HIGH")
                        ? "font-semibold text-red-600"
                        : "font-semibold text-green-600"
                    }
                  >
                    {rule.Risk}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
