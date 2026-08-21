import { cn } from "../../lib";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "-";

export function RiskBadge({ risk }: { risk: RiskLevel }): JSX.Element {
  return (
    <span
      className={cn(
        "inline-flex rounded-full px-3 py-1 text-sm font-extrabold tracking-wide",
        risk === "LOW" && "bg-emerald-300 text-emerald-900",
        risk === "MEDIUM" && "bg-amber-300 text-amber-900",
        risk === "HIGH" && "bg-rose-300 text-rose-900",
        risk === "-" && "bg-slate-500 text-slate-100",
      )}
    >
      {risk}
    </span>
  );
}
