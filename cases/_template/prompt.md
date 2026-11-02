<!-- Shown to the model. Describe what the package does, not what is wrong with it. -->
<!-- The leak check scans everything above '## Answer format' and all sources. -->

## Package overview

Describe the protocol in 2 to 4 neutral sentences: what users do with it and the main objects.

## Entry points in scope

- `module::function`: one-line description of intended behavior.

## Answer format

Audit the package and report the most severe vulnerability, if any.

Answer in JSON:

```json
{"found": true, "bug_class": "arithmetic|access-control|input-validation|object-validation|business-logic|oracle-price|shared-object|upgrade-versioning|none", "location": "module::function", "explanation": "one or two sentences"}
```
