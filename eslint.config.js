import js from "@eslint/js";
import globals from "globals";
import stylistic from "@stylistic/eslint-plugin";

export default [
    js.configs.recommended,
    {
        plugins: {
            "@stylistic": stylistic
        },
        languageOptions: {
            globals: {
                ...globals.browser
            },
            ecmaVersion: 2022,
            sourceType: "module"
        },
        rules: {
            "no-var": ["error"],
            "@stylistic/indent": ["error", 4],
            "@stylistic/linebreak-style": ["error", "unix"],
            "@stylistic/quotes": ["error", "double"],
            "@stylistic/semi": ["error", "always"],
        }
    }
];
