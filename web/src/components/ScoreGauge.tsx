import { PolarAngleAxis, RadialBar, RadialBarChart, ResponsiveContainer } from "recharts";
import type { Verdict } from "../api/types";
import { VERDICT_COLOR } from "./SeverityBadge";

/** Semi-circle 0-100 compromise score (FR-33, US-019). */
export function ScoreGauge({ score, verdict, size = 240 }: { score: number; verdict: Verdict; size?: number }) {
  const color = VERDICT_COLOR[verdict];
  return (
    <div className="relative mx-auto" style={{ width: size, height: size * 0.62 }}>
      <ResponsiveContainer width="100%" height={size}>
        <RadialBarChart data={[{ v: score }]} startAngle={180} endAngle={0} innerRadius="72%" outerRadius="100%" cx="50%" cy="50%" barSize={size / 11}>
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} angleAxisId={0} />
          <RadialBar dataKey="v" background={{ fill: "rgb(var(--border))" }} fill={color} cornerRadius={8} isAnimationActive />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-x-0 text-center" style={{ top: size * 0.26 }}>
        <div className="font-extrabold tabular-nums leading-none" style={{ fontSize: size / 5, color }}>{score}</div>
        <div className="text-muted text-[12px] mt-1">compromise score / 100</div>
      </div>
    </div>
  );
}
