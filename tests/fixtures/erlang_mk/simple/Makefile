PROJECT = myapp
PROJECT_VERSION = 1.0.0

# Production deps (with a line continuation). internal_sibling is a
# workspace app declared by apps/internal_sibling/Makefile.
DEPS = cowlib ranch \
       internal_sibling
DEPS += jsx
REL_DEPS = recon

# Test / build tooling — dev. The $(if ...) Make-function token is skipped.
TEST_DEPS = $(if $(CI),ci.erlang.mk) meck proper
BUILD_DEPS = rebar3

# OTP applications — skipped (not external packages).
LOCAL_DEPS = crypto ssl

dep_cowlib = hex 2.12.1
dep_ranch = git https://github.com/ninenines/ranch 1.8.1
dep_jsx = hex 3.1.0 jsx_renamed

include erlang.mk
