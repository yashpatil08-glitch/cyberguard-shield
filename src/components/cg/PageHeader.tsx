import type { ReactNode } from "react";
import { motion } from "framer-motion";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
      className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between"
    >
      <div>
        {eyebrow && (
          <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-border bg-card/50 px-3 py-1 text-[10px] font-mono uppercase tracking-[0.2em] text-neon">
            <span className="h-1.5 w-1.5 rounded-full bg-neon shadow-[0_0_8px] shadow-neon" />
            {eyebrow}
          </div>
        )}
        <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">{title}</h1>
        {description && (
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground md:text-base">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </motion.div>
  );
}