import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-slate-400 focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-slate-800 text-slate-100 hover:bg-slate-700",
        secondary:
          "border-transparent bg-slate-700 text-slate-200 hover:bg-slate-600",
        destructive:
          "border-red-700 bg-red-950/60 text-red-300",
        outline: "text-slate-200 border-slate-700",
        success: "border-emerald-700 bg-emerald-950/60 text-emerald-300",
        warning: "border-amber-700 bg-amber-950/60 text-amber-300",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
