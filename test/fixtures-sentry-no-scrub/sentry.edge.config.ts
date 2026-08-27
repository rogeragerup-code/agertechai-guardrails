import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  // beforeSend: scrubSentryEvent,
  //   ^ commented out during an incident and never restored. This is the
  //   realistic false-green: the string sits INSIDE the init call, so a check
  //   that does not strip comments first will accept it.
  tracesSampleRate: 0,
});
