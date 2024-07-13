const standard = require('eslint-config-standard');
const jsdoc = require('eslint-plugin-jsdoc');
const preferArrow = require('eslint-plugin-prefer-arrow');
const importPlugin = require('eslint-plugin-import');
const typescriptEslint = require('@typescript-eslint/eslint-plugin');
const n = require('eslint-plugin-n');
const promise = require('eslint-plugin-promise');

module.exports = [
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        browser: true,
        es6: true,
        node: true,
        __: true,
        $: true,
        frappe: true,
        cur_frm: true,
        cur_dialog: true,
        moment: true,
        in_list: true,
        open_url_post: true,
        refresh_field: true,
        locals: true,
        location: true,
      },
    },
    plugins: {
      jsdoc,
      preferArrow,
      import: importPlugin,
      n,
      promise,
      '@typescript-eslint': typescriptEslint,
    },
    rules: {
      ...standard.rules,
      'arrow-parens': ['off', 'as-needed'],
      'comma-dangle': 'off',
      complexity: 'off',
      'constructor-super': 'error',
      curly: 'off',
      'dot-notation': 'error',
      'eol-last': 'off',
      eqeqeq: ['error', 'smart'],
      'guard-for-in': 'error',
      'id-blacklist': 'off',
      'id-match': 'off',
      'import/order': 'off',
      'max-classes-per-file': 'off',
      'max-len': [
        'error',
        {
          code: 150,
        },
      ],
      'new-parens': 'error',
      'no-bitwise': 'error',
      'no-caller': 'error',
      'no-cond-assign': 'error',
      'no-console': 'error',
      'no-debugger': 'error',
      'no-empty': 'off',
      'no-eval': 'error',
      'no-fallthrough': 'off',
      'no-invalid-this': 'off',
      'no-new-wrappers': 'error',
      'no-shadow': 'off',
      '@typescript-eslint/no-shadow': ['error'],
      'no-throw-literal': 'error',
      'no-trailing-spaces': 'error',
      'no-undef-init': 'error',
      'no-underscore-dangle': 'off',
      'no-unsafe-finally': 'error',
      'no-unused-expressions': 'off',
      'no-unused-labels': 'error',
      'no-var': 'error',
      'object-shorthand': 'error',
      'one-var': ['off', 'never'],
      'prefer-arrow/prefer-arrow-functions': [
        'off',
        {
          disallowPrototype: true,
          singleReturnOnly: false,
          classPropertiesAllowed: false,
        },
      ],
      'prefer-const': 'error',
      'require-await': 'off',
      radix: 'error',
      semi: 'off',
      'space-before-function-paren': 'off',
      'spaced-comment': 'error',
      'use-isnan': 'error',
      'valid-typeof': 'off',
    },
  },
];
