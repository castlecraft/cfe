# Project TODO: Enhance `auth.py` with Testing and New Features

This document outlines the steps to improve the `castlecraft/auth.py` module by adding comprehensive test coverage and implementing a new hybrid authentication flow using Test-Driven Development (TDD).

## Phase 1: Establish Test Coverage for Existing `auth.py`

The goal of this phase is to ensure the current authentication logic is fully tested and stable before introducing changes. We will use `pytest` and `unittest.mock` to isolate the code from the Frappe framework and external services.

- [x] **Setup Test Environment** (Complete)
  - [x] Create a `tests` directory within the `castlecraft` app if it doesn't exist.
  - [x] Create a test file, e.g., `tests/test_auth.py`.
  - [x] Ensure `pytest` is installed and configured in the development environment.

- [x] **Write Tests for `validate_bearer_with_introspection()`** (Complete)
  - [x] **Mock Dependencies:**
    - [x] Mock `frappe` calls: `frappe.cache()`, `frappe.get_value`, `frappe.db.exists`, `frappe.set_user`, `frappe.get_conf`, `frappe.log_error`, `frappe.new_doc`, `frappe.get_doc`.
    - [x] Mock `requests.post` to simulate calls to the introspection endpoint.
  - [x] **Test Scenarios:**
    - [x] Test with a valid, uncached token that successfully introspects.
    - [x] Test with a valid, cached token to ensure it bypasses the HTTP request.
    - [x] Test with an invalid or expired token.
    - [x] Test with a valid token for a user that does not exist in Frappe (`create_user` is enabled).
      - [x] Verify `create_and_save_user` is called.
      - [x] Verify user is created with correct roles and claims.
    - [x] Test with `fetch_user_info` enabled, ensuring `request_user_info` is called.
    - [x] Test with a valid token but `create_user` is disabled for a non-existent user (should fail authentication).
    - [x] Test failure when the introspection endpoint is not configured.

- [x] **Write Tests for `validate_bearer_with_jwt_verification()`** (Complete)
  - [x] **Mock Dependencies:**
    - [x] Mock `frappe` calls (similar to introspection tests).
    - [x] Mock `requests.get` to simulate fetching keys from the JWKS endpoint.
    - [x] Mock `jwt.decode` and related functions if needed, or provide mock keys for real decoding.
  - [x] **Test Scenarios:**
    - [x] Test with a valid, signed JWT for an existing user.
    - [x] Test with a JWT that has an invalid signature or incorrect `aud` (audience).
    - [x] Test with an expired JWT.
    - [x] Test with a valid JWT for a user that does not exist (`create_user` is enabled).
    - [x] Test with a valid, cached JWT to ensure it bypasses full validation.

- [x] **Write Tests for Helper Functions** (Complete)
  - [x] Test `get_idp()` to ensure it correctly fetches the named IDP or the default one.
  - [x] Test `create_and_save_user()` to verify it correctly maps claims to the `User` and `CFE User Claim` doctypes.

## Phase 2: TDD for Enhanced JWT Verification Flow

This phase focuses on enhancing the existing "JWT Verification" flow by:

1.  Using the `fetch_user_info` checkbox to optionally fetch user details from a `profile_endpoint` after validating the JWT.
2.  Making the JWT audience claim (`aud`) configurable to support providers like AWS Cognito which may use a different claim (e.g., `client_id`).

- [x] **Step 1: Write the Failing Tests**
  - [x] In `tests/test_auth.py`, add new tests for the enhanced JWT flow.
  - [x] **Test Scenario 1: JWT with User Info Fetching**
    - [x] Configure a mock IDP with `authorization_type` as `JWT Verification` and `fetch_user_info` enabled.
    - [x] Create a valid JWT that might not contain an email claim.
    - [x] Mock the JWKS endpoint for signature validation.
    - [x] Mock the `profile_endpoint` to return a JSON payload with user details (including email).
    - [x] Call `auth.validate()` and assert that `validate_signature` is called, followed by `request_user_info`.
    - [x] Assert that `frappe.set_user` is called with the email from the userinfo response.
    - [x] Add a similar test for new user creation, asserting that `create_and_save_user` is called with the userinfo payload.
  - [x] **Test Scenario 2: Configurable Audience Claim**
    - [x] Configure a mock IDP with a custom `audience_claim_key` (e.g., `client_id`).
    - [x] Create a JWT that uses `client_id` for audience instead of `aud`.
    - [x] Assert that `validate_signature` correctly validates the token.
  - [x] **Run the tests and confirm they fail** as the implementation is not yet updated.

- [x] **Step 2: Implement the Feature**
  - [x] In `auth.py`, modify `validate_bearer_with_jwt_verification(token, idp)`:
    - [x] After `validate_signature` succeeds, check if `idp.fetch_user_info` is true and `idp.profile_endpoint` is set.
    - [x] If so, call `request_user_info(token, idp)` and use its response as the primary source for `user_data`. Otherwise, use the JWT payload.
    - [x] Base the user lookup and creation logic on this `user_data`.
  - [x] In `auth.py`, modify `validate_signature(token, idp)`:
    - [x] Read a new `audience_claim_key` field from the IDP, defaulting to `"aud"`.
    - [x] When calling `jwt.decode`, adjust the parameters to handle audience validation based on this configurable key.
  - [x] Add the `audience_claim_key` field to the `CFE Identity Provider` DocType.

- [x] **Step 3: Make the Tests Pass**
  - [x] Run the test suite again.
  - [x] Debug and refine the implementation until the new test case passes.

- [ ] **Step 4: Refactor and Add More Tests**
  - [x] Refactor the code for clarity and to remove duplication. Consider if `validate_bearer_with_introspection` and the new function can share logic for user lookup, creation, and caching.
  - [ ] Add edge-case tests:
    - [x] An invalid JWT should fail before calling the userinfo endpoint.
    - [ ] The flow should fail gracefully if the userinfo endpoint returns an error.

## Phase 3: Finalization and Documentation

- [ ] **Review and Merge**
  - [ ] Ensure all new and existing tests are passing.
  - [ ] Create a Pull/Merge Request with the changes.
  - [ ] Conduct a final code review.

- [ ] **Update Documentation**
  - [ ] Update `README.md` or other relevant documentation to explain the new `JWT with Userinfo` authorization type and its configuration.
