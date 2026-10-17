# LIM
An Android library for Local Identity Management support between apps.

## Adopting it

One dependency, `dev.eryalabs.lim:lim`, from Maven Central — which a new Android project already
resolves, so there is nothing else to configure. LIM needs `minSdk 24`, and Gson is its only
runtime dependency. The coordinate and the SDK floor are both checked against this repository's
build file, so neither can drift from what the library is actually built for.

The version is not printed on this page, on purpose. The guide's Setup section is the one place
that tells you which version to depend on, and a test holds it to the coordinate this repository's
build file declares, so bumping one reddens the other. The CHANGELOG is the record of what each
version changed, and whether it has gone out yet. A copy on the front page would be neither of
those, and the one nobody checks.

## Integration

[docs/INTEGRATION.md](docs/INTEGRATION.md) is the guide: setup, checking whether a vault is
installed at all, sign-up and its required and optional fields, query, login, handling a refusal,
the rules an integration must not break, what to keep when you minify your app, and how to test
your integration without a vault. Every Kotlin snippet in it is quoted verbatim out of a test that
runs, so the guide cannot drift from the library.

Writing the other half — the app that holds the data and answers those requests?
[docs/VAULT.md](docs/VAULT.md) is the vault author's page: what a vault answers for, how to route
an incoming request, and how to read a share request. Its snippets are pinned the same way.
