const accentColor: Record<string, string> = {
  red: "before:bg-signal-red",
  amber: "before:bg-signal-amber",
  teal: "before:bg-signal-teal",
  neutral: "before:bg-border",
};

export default function StatTile({
  label,
  value,
  accent = "neutral",
  hero = false,
}: {
  label: string;
  value: string | number;
  accent?: "red" | "amber" | "teal" | "neutral";
  hero?: boolean;
}) {
  return (
    <div
      className={`relative border border-border bg-surface px-5 py-4 before:absolute before:inset-x-0 before:top-0 before:h-[2px] ${accentColor[accent]}`}
    >
      <div
        className={`font-display font-600 tabular-nums text-text ${
          hero ? "text-[40px] leading-none" : "text-2xl"
        }`}
      >
        {value}
      </div>
      <div className="mt-2 text-sm text-text-dim">{label}</div>
    </div>
  );
}
