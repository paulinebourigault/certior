import "@/styles/globals.css"
import type { Metadata } from "next"

export const metadata: Metadata = {
  title: "Certior | Command Center",
  description: "The Transparent Box for AI Agents",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <head>
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;12..96,500;12..96,600;12..96,700;12..96,800&family=JetBrains+Mono:wght@300;400;500;600&family=Outfit:wght@300;400;500;600;700&display=swap" />
      </head>
      <body>
        {children}
      </body>
    </html>
  )
}
