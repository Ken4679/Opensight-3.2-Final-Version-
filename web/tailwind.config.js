/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        darkBg: '#0d1117',
        darkCard: '#161b22',
        darkBorder: '#30363d',
      }
    },
  },
  plugins: [],
}
