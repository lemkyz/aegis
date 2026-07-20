import security from "eslint-plugin-security";
import tsParser from "@typescript-eslint/parser";

const securityRules = Object.fromEntries(
  Object.keys(security.rules).map((ruleName) => [
    `security/${ruleName}`,
    "warn",
  ]),
);

export default [
  {
    files: ["**/*.{js,jsx,mjs,cjs}"],
    plugins: {
      security,
    },
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
    },
    rules: securityRules,
  },
  {
    files: ["**/*.{ts,tsx,mts,cts}"],
    plugins: {
      security,
    },
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
    rules: securityRules,
  },
];
