/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "hsl(206 56% 7%)",
        foreground: "hsl(202 53% 95%)",
        card: "hsl(205 42% 12%)",
        muted: "hsl(204 22% 70%)",
        border: "hsl(201 33% 26%)",
        accent: "hsl(168 73% 47%)",
      },
      fontFamily: {
        display: ["Sora", "sans-serif"],
        sans: ["Manrope", "sans-serif"],
      },
      keyframes: {
        rise: {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        rise: "rise 400ms ease-out",
      },
    },
  },
  plugins: [],
};
