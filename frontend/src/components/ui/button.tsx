import type React from "react";
import { cn } from "../../lib";

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement>;

export function Button({ className, ...props }: ButtonProps): JSX.Element {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center rounded-xl px-5 py-3 font-semibold text-slate-950",
        "bg-gradient-to-r from-accent to-cyan-300 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    />
  );
}
