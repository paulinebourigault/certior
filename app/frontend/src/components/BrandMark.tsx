interface Props {
  size?: number;
  variant?: "editorial" | "monogram" | "seal";
  withWordmark?: boolean;
  subtitle?: string;
  className?: string;
}

function MonogramSymbol({ size }: { size: number }) {
  return (
    <div className="relative text-slate-900" style={{ width: size, height: size }} aria-hidden="true">
      <svg viewBox="0 0 64 64" fill="none" className="h-full w-full text-current">
        <path
          d="M47.6 19c-3.6-5-9.4-8-16-8-12.1 0-20.6 8.9-20.6 21s8.5 21 20.6 21c6.5 0 12.2-2.8 15.8-7.7"
          stroke="currentColor"
          strokeWidth="4.8"
          strokeLinecap="round"
        />
        <path d="M28 20.5H39.5" stroke="currentColor" strokeWidth="4.8" strokeLinecap="round" />
        <path d="M39.5 20.5V43.5" stroke="currentColor" strokeWidth="4.8" strokeLinecap="round" />
        <path d="M28 43.5H39.5" stroke="currentColor" strokeWidth="4.8" strokeLinecap="round" />
      </svg>
    </div>
  );
}

function SealSymbol({ size }: { size: number }) {
  return (
    <div className="relative text-slate-900" style={{ width: size, height: size }} aria-hidden="true">
      <svg viewBox="0 0 64 64" fill="none" className="h-full w-full text-current">
        <circle cx="32" cy="32" r="23" stroke="currentColor" strokeWidth="3.6" />
        <circle cx="32" cy="32" r="17.5" stroke="currentColor" strokeWidth="1.8" opacity="0.55" />
        <path d="M28.5 22H38V42H28.5" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="23" cy="32" r="2.8" fill="currentColor" />
      </svg>
    </div>
  );
}

export default function BrandMark({
  size = 44,
  variant = "monogram",
  withWordmark = true,
  subtitle = "verified agentic operations",
  className = "",
}: Props) {
  const compactWordmarkSize = size >= 64 ? 22 : size >= 48 ? 18 : 15;
  const compactSubtitleSize = size >= 64 ? 10.5 : size >= 48 ? 10 : 9;
  const editorialWordmarkSize = size >= 72 ? 30 : size >= 60 ? 25 : 20;
  const editorialSubtitleSize = size >= 72 ? 10.5 : 10;

  if (variant === "seal") {
    return (
      <div className={`inline-flex items-center gap-3 ${className}`.trim()}>
        <SealSymbol size={size} />
        {withWordmark && (
          <div className="min-w-0 leading-none">
            <p
              className="font-display font-semibold tracking-[0.16em] text-slate-900"
              style={{ fontSize: `${compactWordmarkSize}px` }}
            >
              CERTIOR STUDIO
            </p>
            <p
              className="mt-1.5 uppercase tracking-[0.24em] text-slate-500"
              style={{ fontSize: `${compactSubtitleSize}px` }}
            >
              {subtitle}
            </p>
          </div>
        )}
      </div>
    );
  }

  if (variant === "editorial") {
    return (
      <div className={`inline-flex flex-col gap-3 ${className}`.trim()}>
        <div className="leading-none text-slate-900">
          <p
            className="font-display font-semibold tracking-[0.22em]"
            style={{ fontSize: `${editorialWordmarkSize}px` }}
          >
            CERTIOR STUDIO
          </p>
        </div>
        <div className="inline-flex items-center gap-2.5">
          <SealSymbol size={Math.max(18, Math.round(size * 0.28))} />
          <p
            className="uppercase tracking-[0.24em] text-slate-500"
            style={{ fontSize: `${editorialSubtitleSize}px` }}
          >
            {subtitle}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className={`inline-flex items-center gap-3.5 ${className}`.trim()}>
      <MonogramSymbol size={size} />

      {withWordmark && (
        <div className="min-w-0 leading-none">
          <p
            className="font-display font-semibold tracking-[0.14em] text-slate-900"
            style={{ fontSize: `${compactWordmarkSize}px` }}
          >
            CERTIOR STUDIO
          </p>
          <p
            className="mt-1.5 uppercase tracking-[0.24em] text-slate-500"
            style={{ fontSize: `${compactSubtitleSize}px` }}
          >
            {subtitle}
          </p>
        </div>
      )}
    </div>
  );
}