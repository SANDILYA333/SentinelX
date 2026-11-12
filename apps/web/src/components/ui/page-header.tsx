"use client";

import React from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { type LucideIcon, ChevronRight } from "lucide-react";

interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  icon?: LucideIcon;
  breadcrumbs?: BreadcrumbItem[];
  actions?: React.ReactNode;
  className?: string;
}

export function PageHeader({
  title,
  subtitle,
  icon: Icon,
  breadcrumbs,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div
      className={cn(
        "flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800/80 shrink-0",
        className
      )}
    >
      <div className="space-y-1">
        {breadcrumbs && breadcrumbs.length > 0 && (
          <nav className="flex items-center gap-1.5 text-xs text-slate-500 font-mono mb-1">
            {breadcrumbs.map((crumb, idx) => {
              const isLast = idx === breadcrumbs.length - 1;
              return (
                <React.Fragment key={crumb.label}>
                  {crumb.href && !isLast ? (
                    <Link
                      href={crumb.href}
                      className="hover:text-slate-300 transition-colors"
                    >
                      {crumb.label}
                    </Link>
                  ) : (
                    <span className={cn(isLast && "text-slate-300 font-semibold")}>
                      {crumb.label}
                    </span>
                  )}
                  {!isLast && <ChevronRight className="w-3 h-3 text-slate-600" />}
                </React.Fragment>
              );
            })}
          </nav>
        )}

        <div className="flex items-center gap-2.5">
          {Icon && <Icon className="w-6 h-6 text-blue-400 shrink-0" />}
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            {title}
          </h1>
        </div>

        {subtitle && (
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            {subtitle}
          </p>
        )}
      </div>

      {actions && (
        <div className="flex items-center gap-2.5 flex-wrap shrink-0">
          {actions}
        </div>
      )}
    </div>
  );
}
