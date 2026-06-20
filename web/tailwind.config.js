/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        border: "hsl(var(--border))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        muted: { DEFAULT: "hsl(var(--muted))", foreground: "hsl(var(--muted-foreground))" },
        primary: { DEFAULT: "hsl(var(--primary))", foreground: "hsl(var(--primary-foreground))" },
        destructive: { DEFAULT: "hsl(var(--destructive))", foreground: "hsl(var(--destructive-foreground))" },
        card: { DEFAULT: "hsl(var(--card))", foreground: "hsl(var(--card-foreground))" },
        brand: { accent: "hsl(var(--brand-accent))", foreground: "hsl(var(--brand-accent-foreground))" },
        console: { accent: "hsl(var(--console-accent))" },
        operate: { DEFAULT: "hsl(var(--operate))", foreground: "hsl(var(--operate-foreground))" },
        observe: { DEFAULT: "hsl(var(--observe))", foreground: "hsl(var(--observe-foreground))" },
        disclose: { DEFAULT: "hsl(var(--disclose))", foreground: "hsl(var(--disclose-foreground))" },
        risk: {
          critical: "hsl(var(--risk-critical))",
          high: "hsl(var(--risk-high))",
          medium: "hsl(var(--risk-medium))",
          low: "hsl(var(--risk-low))",
          none: "hsl(var(--risk-none))",
        },
        status: {
          success: "hsl(var(--status-success))",
          warning: "hsl(var(--status-warning))",
          neutral: "hsl(var(--status-neutral))",
          info: "hsl(var(--status-info))",
        },
      },
      borderRadius: {
        control: "var(--radius-control)",
        panel: "var(--radius-panel)",
      },
      boxShadow: {
        elevation1: "var(--elevation-1)",
        elevation2: "var(--elevation-2)",
        elevation3: "var(--elevation-3)",
      },
      fontSize: {
        caption: ["var(--font-size-caption)", { lineHeight: "var(--line-height-caption)" }],
        body: ["var(--font-size-body)", { lineHeight: "var(--line-height-body)" }],
        title: ["var(--font-size-title)", { lineHeight: "var(--line-height-title)" }],
        heading: ["var(--font-size-heading)", { lineHeight: "var(--line-height-heading)" }],
        display: ["var(--font-size-display)", { lineHeight: "var(--line-height-display)" }],
      },
      spacing: {
        compact: "var(--density-compact)",
        comfortable: "var(--density-comfortable)",
      },
    },
  },
  plugins: [],
};
