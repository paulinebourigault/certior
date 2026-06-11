/* ──────────────────────────────────────────────────────────────
   404 - custom not-found page.
   ────────────────────────────────────────────────────────────── */

import Head from "next/head";
import Link from "next/link";

export default function NotFoundPage() {
  return (
    <>
      <Head>
        <title>Certior Studio - Page Not Found</title>
      </Head>

      <div className="flex min-h-[60vh] items-center justify-center p-6">
        <div className="text-center space-y-4">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-base-800 border border-base-700">
            <span className="text-3xl font-display font-bold text-gray-600">404</span>
          </div>
          <h1 className="text-lg font-semibold font-display text-gray-200">Page Not Found</h1>
          <p className="text-sm text-gray-500 max-w-xs mx-auto">
            The page you're looking for doesn't exist or has been moved.
          </p>
          <Link href="/" className="btn-primary inline-flex">
            Back to Dashboard
          </Link>
        </div>
      </div>
    </>
  );
}
