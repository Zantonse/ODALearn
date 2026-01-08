/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        okta: {
          blue: '#007dc1',
          dark: '#00297a',
          light: '#e6f4ff',
        }
      }
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
