import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    rules: {
      // Full-page navigation intentionally clears sensitive client-side state.
      "@next/next/no-html-link-for-pages": "off",
      // User uploads use a same-origin, content-validated R2 endpoint with
      // unknown dimensions, so the framework image optimizer is not suitable.
      "@next/next/no-img-element": "off",
      // Async loaders own their explicit loading state before awaiting I/O.
      "react-hooks/set-state-in-effect": "off",
    },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
