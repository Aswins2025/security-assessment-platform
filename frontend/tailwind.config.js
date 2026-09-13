/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        critical: "#7f1d1d",
        high: "#dc2626",
        medium: "#f59e0b",
        low: "#22c55e",
        info: "#94a3b8",
      },
    },
  },
  plugins: [],
}
