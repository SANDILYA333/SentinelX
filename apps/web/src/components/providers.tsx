"use client";

import * as React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EvidenceDrawerProvider } from "@/components/evidence-drawer";
import { ToastProvider } from "@/components/ui/toast";
import { useEventStream } from "@/hooks/useEventStream";

function GlobalStreamListener() {
  useEventStream();
  return null;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = React.useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 5000,
            refetchOnWindowFocus: false,
            retry: 1,
          },
        },
      })
  );

  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <EvidenceDrawerProvider>
          <GlobalStreamListener />
          {children}
        </EvidenceDrawerProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}
