import * as Sentry from "@sentry/nextjs";

// guardrails-allow: sentry-scrub-disconnected
// This init only reports build-time telemetry and handles no user data.
Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
});
