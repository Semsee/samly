# CHANGELOG

### v1.5.0 (Semsee fork)
+   Vendor the `esaml` 4.6.0 Erlang modules into `src/` and drop the Hex dependency,
    removing `cowboy`, `cowlib` and `ranch` from the dependency tree
+   Disable XML entity expansion when parsing SAML messages, encrypted assertions
    and remote metadata (CVE-2026-28809)
+   `xmerl_dsig:verify/2` rejects RSA-SHA1 signatures (`insecure_algorithm`) and
    SHA-1 digests (`insecure_digest`), returns `unsupported_algorithm` /
    `unsupported_digest` for anything other than SHA-256/384/512, checks the
    `ds:Reference` URI against the signed element's `ID` (`bad_reference`),
    hashes with the declared `DigestMethod`, and compares digests in constant time
+   Cap DEFLATE-inflated payloads at 1 MiB (`inflated_payload_too_large`)
+   Reject assertions whose `NotBefore` is more than 3 minutes in the future
    (`assertion_not_yet_valid`)
+   Detect replayed responses with `esaml_util:check_dupe_ets/2` (`duplicate`)
+   Store the AuthnRequest `ID` in the session and require the SP-initiated
    response's `InResponseTo` to match (`invalid_in_response_to`)
+   Treat xmerl parse failures (which `exit`) as `invalid_response` instead of
    crashing the request process
+   `esaml:config/2` reads from `config :samly, esaml: [...]` now that there is
    no `esaml` application
+   Replace deprecated `catch Expr` with `try`/`catch` (OTP 29 warnings)
+   `esaml_sp:validate_assertion/3` reports signature failures as
    `{error, {envelope | assertion, Reason}}` instead of nesting a second
    `{error, Reason}` tuple inside

### v1.4.0
+   remove uri double encoding thanks to @DiaanEngelbrecht
+   fix esaml initialization thanks to @bopm
+   check and enforce session expiration (CVE-2024-25718) thanks to @idyll

### v1.3.0
+   Added dialyzer checks
+   Changed internal function layout to report errors more granularly
+   Verified with updates to esaml dependency
+   Client can refresh the runtime provider config without restarting the app from [bernardd](https://github.com/dropbox/samly/pull/7)

### v1.2.0
+   Metadata can be specified directly in the IdP config rather than requiring a file
+   Bumps dependencies

### v1.1.0
+   Updated minor version due to dependency updates requiring potential language version bumps
+   Removed Inch CI
+   Updated dependencies for project
+   Removed strict required dependency on `sweet_xml`
+   Use updated version of `esaml` to reduce strict requirements on `cowboy`
+   Updated license copyright

### v1.0.0

+   `target_url` query parameter for the sign-in/sign-out requests must be
    `x-www-form-urlencoded`.

+   Redirect URLs are properly encoded.

+   Switched to `report-to` in content security policy.

+   `cache-control` header value updated.

+   Issue: #33 - Content Security Policy
    Enabled `Content-Security-Policy` in the HTTP response.

+   PR: #41 - Config support for nameid format
    `Samly` uses the nameid format from the IdP metadata XML file.
    It is possible now to override this using `nameid_fomat` config setting.
    If this format information is not present in the IdP metadata XML and not
    specified in the config setting, it defaults to `:transient`.
    Thanks to [calvinb](https://github.com/calvinb) for the PR.

+   Uptake `esaml 4.2` bringing in support for encrypted assertions.
    Check [Assertion Encryption](https://github.com/handnot2/esaml#assertion-encryption)
    for supported encryption algorithms. Use this information to enable assertion
    encryption on IdP. Thanks to [tcrossland](https://github.com/tcrossland)
    for the `esaml` PR.

### v0.10.1

+   Issues: #39, #40 - Downcase response header names
    (PR from [calvinb](https://github.com/calvinb))

### v0.10.0

+   Issue: #31 - Support for Cowboy 2.x
    Uptake `esaml` v4.0.0 which includes support for Cowboy 2.x.
    If support for Cowboy 1.x is needed, you need an override with
    `esaml` v3.6.x in your application `mix.exs` file.

+   Issue: #32 - Support for custom State Storage
    Includes support for ETS and Plug Sessions based authenticated SAML
    assertion storage. It is possible to create custom stores by
    implementing `Samly.State.Store`.

+   Issue: #34 - Included filename in error messages
    Include metadata/cert/key filenames when there is an error relevant to
    those files.

### v0.9.3

+   Uptake `esaml` v3.6.0 that includes fixes for schema validation errors.

### v0.9.2

+   PR merged fixing reopened Issue #16 (from @peterox)

### v0.9.1

+   Remove the need for supplying certificate and key files if the requests are
    not signed (Issue #16). Useful during development when the corresponding
    Identity Provider is setup for unsigned requests/responses. Use signing
    for production deployments. The defaults expect signed requests/responses.

### v0.9.0

+   Issue: #12. Support for IDP initiated SSO flow.

+   Original auth request ID when returned in auth response is made available
    in the assertion subject (SP initiated SSO flows). For IDP initiated
    SSO flows, this will be an empty string.

+   Issue: #14. Remove built-in referer check.
    Not specific to `Samly`. It is better handled by the consuming application.

### v0.8.4

+   Shibboleth Single Logout session match related fix. Uptake `esaml v3.3.0`.

### v0.8.3

+   Generates SP metadata XML that passes XSD validation

### v0.8.2

+   Handle namespaces in Identity Provider Metadata XML file

### v0.8.0

+   Added support for multiple Identity Providers. Check issue: #4.
    Instructions for migrating from v0.7.x available in github project wiki.

### v0.7.2

+   Added `use_redirect_for_idp_req` config parameter. By default `Samly` uses HTTP POST when sending requests to IdP. Set this config parameter to `true` if HTTP redirection should be used instead.

### v0.7.1

+   Added config option (`entity_id`). OOTB uses metadata URI as entity ID. Can be specified (`urn` entity ID for example) to override the default.

### v0.7.0

+   Added config options to control if requests and/or responses are signed or not

### v0.6.3

+   Added Inch CI
+   Corresponding doc updates

### v0.6.2

+   Doc updates
+   Config handling changes and corresponding tests

### v0.6.1

+   `target_url` query parameter form url encoded

### v0.6.0

+   Plug Pipeline config `:pre_session_create_pipeline`
+   Computed attributes available in `Samly.Assertion`
+   Updates to `Samly.Provider` `base_url` config handling
