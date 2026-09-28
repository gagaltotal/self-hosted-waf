/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0A0D12",
        surface: "#12161D",
        "surface-2": "#191F29",
        border: "#242B38",
        text: "#E7E9EC",
        "text-dim": "#8993A4",
        "text-faint": "#4E5768",
        signal: {
          red: "#FF5A5A",
          "red-dim": "#3A1F24",
          amber: "#F5B94D",
          "amber-dim": "#3A2F1A",
          teal: "#46D2BE",
          "teal-dim": "#163330",
          violet: "#A78BFA",
          "violet-dim": "#2A2440",
        },
      },
      fontFamily: {
        display: ["'Space Grotesk'", "ui-sans-serif", "system-ui", "sans-serif"],
        sans: [
          "-apple-system",
          "'Segoe UI'",
          "Roboto",
          "Helvetica",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "'SF Mono'",
          "'Cascadia Code'",
          "'Roboto Mono'",
          "Consolas",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
