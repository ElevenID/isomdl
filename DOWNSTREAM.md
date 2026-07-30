# ElevenID downstream maintenance

This public fork preserves the history and `Apache-2.0 OR MIT` licensing of
[`spruceid/isomdl`](https://github.com/spruceid/isomdl).

ElevenID maintains this fork because Marty currently needs small dependency
security and mdoc interoperability patches that are not available in an
upstream release. The downstream delta should remain narrow, tested, and easy
to retire:

- `ssi-jwk` is upgraded from 0.2 to 0.4.
- Empty `IssuerSigned.nameSpaces` maps are accepted as a valid no-disclosure
  response while non-empty namespaces containing no items remain invalid.
- Upstream `main` is checked monthly and may also be checked manually.
- The sync workflow opens or refreshes a pull request. It never merges.
- Merge conflicts fail visibly and create one tracking issue for manual
  resolution.
- All normal CI must pass before an upstream-sync pull request is merged.

We will adopt a suitable upstream release and remove the downstream dependency
when the required behavior and dependency remediation are available upstream.
Review the need for this fork at least quarterly.
