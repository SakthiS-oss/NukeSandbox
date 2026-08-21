import type React from "react";
import { cn } from "../../lib";

type CardProps = React.HTMLAttributes<HTMLDivElement>;

export function Card({ className, ...props }: CardProps): JSX.Element {
  return (
    <div
      className={cn("rounded-2xl border border-border bg-card/80 backdrop-blur-sm", className)}
      {...props}
    />
  );
}
