export default function AppGuardLogo({ className = "w-7 h-7" }) {
  return (
    <svg
      viewBox="0 0 100 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`${className} flex-shrink-0 drop-shadow-md`}
    >
      {/* Outer Border / Bevel */}
      <path
        d="M50 4 C78 4, 96 16, 96 36 C96 78, 68 106, 50 116 C32 106, 4 78, 4 36 C4 16, 22 4, 50 4 Z"
        fill="#0f172a"
        stroke="#475569"
        strokeWidth="3.5"
      />

      {/* Silver / White Right Base */}
      <path
        d="M50 8 C74 8, 91 18, 91 37 C91 74, 66 101, 50 111 C34 101, 9 74, 9 37 C9 18, 26 8, 50 8 Z"
        fill="#f1f5f9"
      />

      {/* Red Left Half with Serrated / Sawtooth Center Division */}
      <path
        d="M50 8 C26 8, 9 18, 9 37 C9 74, 34 101, 50 111 
           L44 98 L53 91 
           L44 80 L53 72 
           L44 61 L53 53 
           L44 42 L53 34 
           L44 23 L50 8 Z"
        fill="#dc2626"
      />

      {/* Subtle Specular Highlight */}
      <path
        d="M50 8 C74 8, 91 18, 91 37 C91 58, 78 80, 50 95 L50 8 Z"
        fill="white"
        fillOpacity="0.12"
      />
    </svg>
  )
}
