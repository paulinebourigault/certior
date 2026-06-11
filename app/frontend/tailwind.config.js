/** @type {import('tailwindcss').Config} */

/** Helper: make a color value that supports Tailwind's /opacity modifier. */
function withAlpha(hex) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return ({ opacityValue }) =>
    opacityValue === undefined
      ? `rgb(${r} ${g} ${b})`
      : `rgb(${r} ${g} ${b} / ${opacityValue})`;
}

module.exports = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          950: withAlpha("#faf5ee"),
          900: withAlpha("#fff8f1"),
          800: withAlpha("#f2e7d8"),
          700: withAlpha("#d9c8b8"),
          600: withAlpha("#bda894"),
          500: withAlpha("#9c8773"),
        },
        verified: {
          DEFAULT: withAlpha("#6d8e62"),
          dim: withAlpha("#58754f"),
          glow: withAlpha("#9cb091"),
          bg: "rgba(111, 174, 133, 0.12)",
        },
        blocked: {
          DEFAULT: withAlpha("#c37d68"),
          dim: withAlpha("#a96754"),
          bg: "rgba(195, 125, 104, 0.14)",
        },
        warn: {
          DEFAULT: withAlpha("#c49c62"),
          dim: withAlpha("#a77d43"),
          bg: "rgba(196, 156, 98, 0.15)",
        },
        accent: {
          DEFAULT: withAlpha("#c69270"),
          dim: withAlpha("#a97254"),
          glow: withAlpha("#dfb59a"),
          bg: "rgba(198, 146, 112, 0.14)",
        },
        proof: {
          DEFAULT: withAlpha("#9f9bb8"),
          dim: withAlpha("#7d7897"),
          glow: withAlpha("#c1bdd6"),
          bg: "rgba(159, 155, 184, 0.14)",
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', "monospace"],
        sans: ['"Outfit"', "system-ui", "sans-serif"],
        display: ['"Bricolage Grotesque"', "system-ui", "sans-serif"],
      },
      animation: {
        "pulse-verified": "pulseVerified 3s ease-in-out infinite",
        "fade-in": "fadeIn 0.5s ease-out forwards",
        "slide-up": "slideUp 0.4s ease-out forwards",
        "slide-in-right": "slideInRight 0.3s ease-out forwards",
        "scan-line": "scanLine 2.5s ease-in-out infinite",
        "shimmer": "shimmer 2s ease-in-out infinite",
        "glow-ring": "glowRing 3s ease-in-out infinite",
        "count-up": "fadeIn 0.6s ease-out forwards",
        "breathe": "breathe 4s ease-in-out infinite",
      },
      keyframes: {
        pulseVerified: {
          "0%, 100%": { boxShadow: "0 0 0 0 rgba(52, 211, 153, 0.2)" },
          "50%": { boxShadow: "0 0 24px 4px rgba(52, 211, 153, 0.1)" },
        },
        fadeIn: {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        slideUp: {
          from: { opacity: "0", transform: "translateY(12px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        slideInRight: {
          from: { opacity: "0", transform: "translateX(16px)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        scanLine: {
          "0%": { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(300%)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        glowRing: {
          "0%, 100%": { opacity: "0.4", transform: "scale(1)" },
          "50%": { opacity: "0.8", transform: "scale(1.05)" },
        },
        breathe: {
          "0%, 100%": { opacity: "0.5" },
          "50%": { opacity: "1" },
        },
      },
      backgroundImage: {
        "grid-subtle": "linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)",
      },
      backgroundSize: {
        "grid-subtle": "48px 48px",
      },
    },
  },
  plugins: [],
};
