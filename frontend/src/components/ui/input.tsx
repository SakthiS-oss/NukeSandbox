import type React from "react";
import { cn } from "../../lib";

type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

export function Input({ className, ...props }: InputProps): JSX.Element {
  return (
    <input
      className={cn(
        "w-full rounded-xl border border-border bg-slate-900/70 px-4 py-3 text-foreground",
        "outline-none ring-accent/40 placeholder:text-slate-500 focus:ring-2",
        className,
      )}
      {...props}
    />
  );
}
