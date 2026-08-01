# =============================================================================
# cognito.tf — the identity provider (OAuth2 / OIDC JWT authentication)
# =============================================================================
# This is the "front-door authentication" layer the lab previously lacked. API keys (api_gateway.tf)
# identify and throttle a CALLER; they do not authenticate a USER. This file adds an Amazon Cognito
# user pool that issues signed JWTs (OAuth2 / OpenID Connect), and api_gateway.tf attaches a
# COGNITO_USER_POOLS authorizer that validates those tokens at the edge — so by the time a request
# reaches the Lambda, the caller's identity has already been cryptographically proven.
#
# Why this matters — it removes the lab's one self-asserted-identity weakness:
#   Before: the handler read `user` (and its clearance) from the request BODY. Anyone could claim to
#           be "b.taylor" with Restricted clearance. That was a deliberate demo affordance, but it is
#           NOT how you authorize a real system.
#   After:  identity comes from a VERIFIED token claim (cognito:username), and clearance comes from a
#           `custom:clearance` claim that Cognito mints and the app client cannot write. The
#           retrieval-layer authorization check (src/chat/handler.py) is unchanged — but now it runs
#           against claims that can't be forged, turning "principal -> clearance -> per-document
#           decision" into genuine claims-based access control (OWASP LLM: identity & authorization).
#
# The pool exists in BOTH lab modes (creating/destroying users on every controls toggle would be
# painful and unrealistic — your IdP doesn't come and go). What the controls_enabled toggle changes
# is whether the API METHOD actually enforces the token (see api_gateway.tf): hardened = token
# required, baseline = authorization "NONE" so the original self-asserted-identity attack still
# replays.
# -----------------------------------------------------------------------------

# The user pool: the identity store + token issuer. This is the OIDC provider; its hosted JWKS
# endpoint (https://cognito-idp.<region>.amazonaws.com/<pool-id>/.well-known/jwks.json) is what API
# Gateway uses to verify token signatures.
resource "aws_cognito_user_pool" "this" {
  name = "${local.prefix}-users"

  # Passwords are a real credential even in a lab — enforce a non-trivial policy so the pool models
  # production hygiene rather than teaching a weak default.
  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  # Custom attribute surfaced in the JWT as `custom:clearance`. This is the claim the retrieval-layer
  # authorization check consumes. mutable = true lets an ADMIN change a user's clearance; the app
  # client's write_attributes (below) deliberately EXCLUDES it, so a signed-in user cannot raise
  # their own clearance via UpdateUserAttributes — the token's clearance is trustworthy precisely
  # because the holder can't mint it.
  schema {
    name                     = "clearance"
    attribute_data_type      = "String"
    mutable                  = true
    developer_only_attribute = false
    string_attribute_constraints {
      min_length = 1
      max_length = 32
    }
  }

  # Don't leak whether a username exists on failed auth (anti-enumeration).
  # (Set on the client via prevent_user_existence_errors below.)

  tags = { Component = "identity" }
}

# The app client: how the demo (and a real front-end) exchanges credentials for tokens.
resource "aws_cognito_user_pool_client" "this" {
  name         = "${local.prefix}-client"
  user_pool_id = aws_cognito_user_pool.this.id

  # No client secret: this is a PUBLIC client (the pattern for SPAs / CLIs). It keeps the demo's
  # token fetch a plain initiate-auth with no SECRET_HASH computation. A confidential server-side
  # client would set generate_secret = true.
  generate_secret = false

  # USER_PASSWORD_AUTH lets the demo trade username+password for tokens directly (the OAuth2
  # resource-owner-password flow — convenient for a lab; a production web app would use the
  # authorization-code flow via the hosted UI instead). Refresh-token flow supports renewal.
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  # Anti-enumeration: return a generic failure whether or not the username exists.
  prevent_user_existence_errors = "ENABLED"

  # read_attributes MUST include custom:clearance or the claim won't appear in the token the
  # retrieval check reads. write_attributes intentionally OMITS custom:clearance (and does not
  # include it anywhere) so the client can never write it — the self-elevation guard described above.
  read_attributes  = ["email", "custom:clearance"]
  write_attributes = ["email"]

  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30
  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
}

# ---------- Seed users mirroring corpus/manifest.json clearances ----------
# One Cognito user per manifest identity, each stamped with the SAME clearance the manifest assigns,
# so the existing scenarios replay unchanged — except identity/clearance now arrive as verified
# claims instead of body fields. This keeps the corpus manifest and the IdP in agreement (in a real
# system the manifest's per-user table would BE the directory; here we seed both from one list).
locals {
  # Mirror of corpus/manifest.json "users" — kept here so the pool and the manifest can't silently
  # drift. If you add a user to the manifest, add it here (and vice-versa).
  seed_users = {
    "c.jones"    = "Internal"
    "a.williams" = "Internal"
    "d.brown"    = "Confidential"
    "e.davis"    = "Internal"
    "b.taylor"   = "Restricted"
  }
}

resource "aws_cognito_user" "seed" {
  for_each = local.seed_users

  user_pool_id = aws_cognito_user_pool.this.id
  username     = each.key

  attributes = {
    email              = "${each.key}@lab.example"
    email_verified     = "true"
    "custom:clearance" = each.value
  }

  # A permanent password so the demo can authenticate non-interactively. This is a LAB demo
  # credential — override var.demo_user_password (and treat these accounts as disposable). Terraform
  # stores this in state, so the state backend must be protected (same caveat as the API key).
  password = var.demo_user_password

  # Changing the clearance attribute out-of-band shouldn't be fought by Terraform mid-demo, but the
  # password managing the account should stay declarative. (No lifecycle ignore needed by default.)
}
