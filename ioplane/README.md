# ioplane tooling

Additional quality gate for the ioplane fork. Not part of upstream PRs.

- `golangci.yml`: golangci-lint v2 configuration with every linter enabled
  except deprecated ones and the ones requiring a project allowlist.
- Run on changed code only:

```bash
golangci-lint run -c ioplane/golangci.yml --new-from-merge-base=upstream/main ./...
golangci-lint fmt -c ioplane/golangci.yml --diff <files>
```

Verified with golangci-lint v2.14.0 built with Go 1.27, on Go 1.27.1.
