# download-base-artifact

> Download the base artifact for the current workflow.

For pull requests, this action looks at the branch the pull request is open against, finds the last successful workflow run for that branch, and downloads the artifact for that workflow run. For pushes, this action looks as the commit id for the branch before the push happened, finds a successful workflow run for that commit (falls back to the last successful for the branch if that commit broke the build), and downloads the artifact for that workflow run.


## Usage

This action could be used to:

* Download size metadata about the previous build and compare it against sizes for the current build
* Download the build output of a previous build to benchmark against the output of the current build
* Other things I haven't thought of!

```yaml
name: Compare artifacts

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      # Generate the artifact for this build
      - name: Build artifact
        run: echo "$GITHUB_RUN_NUMBER" > test-artifact.txt

      # Download the base artifact using this action
      - uses: andrewiggins/download-base-artifact@v1
        with:
          artifact: "test-artifact.txt"
          path: base

      # Compare the two artifacts as you wish
      - run: diff test-artifact.txt base/test-artifact.txt
```

## Inputs

### artifact

The name of the artifact to download. Required.

### github_token

The GITHUB_TOKEN for the current workflow run (optional)

### workflow

The workflow file name that generates the desired artifact. Defaults to the current workflow.

### path

The path to download the artifact to. Defaults to the current working directory.
