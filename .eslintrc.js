module.exports = {
  env: {
    es2021: true,
    node: true,
  },
  extends: ["eslint:recommended", "plugin:@typescript-eslint/recommended"],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
    root: true,
    allowImportExportEverywhere: true,
  },
  plugins: ["@typescript-eslint", "import"],
  rules: {
    "@typescript-eslint/ban-ts-comment": 1,
    "no-console": ["error", { allow: ["warn", "error", "info"] }],
    "spaced-comment": "error",
    "no-unused-vars": "warn",
    "@typescript-eslint/no-unused-vars": "error",
    "@typescript-eslint/array-type": ["error", { default: "array" }],
    "import/no-anonymous-default-export": ["error"],
    "import/order": [
      "error",
      {
        groups: ["builtin", "external", "internal", "parent", "sibling", "index"],
        "newlines-between": "always",
        alphabetize: {
          order: "asc",
          caseInsensitive: true,
        },
      },
    ],
    "import/first": "error",
    "import/newline-after-import": "error",
    "import/no-duplicates": "error"
  },
}
