import { motion } from "framer-motion";

/**
 * Radial gauge. score 0-100 — color shifts with severity.
 * For risk gauges set `inverted` to true so higher = worse.
 */
export function ScoreGauge({
  value,
  label,
  inverted = false,
  size = 180,
}: {
  value: number;
  label?: string;
  inverted?: boolean;
  size?: number;
}) {
  const v = Math.max(0, Math.min(100, value));
  const effective = inverted ? 100 - v : v;
  const color =
    effective >= 75
      ? "var(--neon)"
      : effective >= 50
        ? "var(--cyber)"
        : effective >= 25
          ? "var(--warn)"
          : "var(--danger)";

  const r = (size - 20) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (v / 100) * c;

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke="color-mix(in oklch, var(--border) 60%, transparent)"
          strokeWidth={10}
          fill="none"
        />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke={color}
          strokeWidth={10}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.1, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 8px ${color})` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="text-4xl font-semibold tabular-nums"
          style={{ color }}
        >
          {Math.round(v)}
        </motion.div>
        {label && (
          <div className="mt-1 text-[10px] font-mono uppercase tracking-[0.2em] text-muted-foreground">
            {label}
          </div>
        )}
      </div>
    </div>
  );
}