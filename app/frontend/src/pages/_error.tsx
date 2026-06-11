import type { NextPageContext } from "next";
import Head from "next/head";
import Link from "next/link";

interface ErrorPageProps {
  statusCode?: number;
}

function getMessage(statusCode?: number) {
  if (statusCode === 404) {
    return "The page you requested could not be found.";
  }
  if (statusCode && statusCode >= 500) {
    return "Studio hit a server error while loading this page.";
  }
  return "Studio could not complete this request.";
}

export default function ErrorPage({ statusCode }: ErrorPageProps) {
  return (
    <>
      <Head>
        <title>Certior Studio - Error</title>
      </Head>

      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="panel-warm w-full max-w-lg rounded-[32px] px-8 py-10 text-center space-y-5">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-[20px] border border-base-700/50 bg-white/82 text-slate-900">
            <span className="text-2xl font-display font-semibold">{statusCode ?? "!"}</span>
          </div>
          <div className="space-y-2">
            <p className="label">Studio error</p>
            <h1 className="text-2xl font-display text-slate-900">Something interrupted the page load</h1>
            <p className="text-sm leading-6 text-slate-600">{getMessage(statusCode)}</p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Link href="/" className="btn-primary px-5 py-3">
              Back to dashboard
            </Link>
            <button type="button" onClick={() => window.location.reload()} className="btn-ghost border border-base-700/60 px-5 py-3">
              Reload
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

ErrorPage.getInitialProps = ({ res, err }: NextPageContext): ErrorPageProps => {
  const statusCode = res?.statusCode ?? err?.statusCode ?? 500;
  return { statusCode };
};