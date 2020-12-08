# Contributing

## Publishing a new version

1. Update package.json with new version
2. Check in package.json version change with commit message (e.g. "Release 1.1.0")
3. Create release in GitHub with notes on changes
4. Check out new tag (e.g. "v1.1.0")
5. Move major version to new tag (e.g. "v1"):
   - `git push origin :refs/tags/<major_ver_tagname>; git tag -fa <major_ver_tagname>; git push origin master --tags`
   - Message for major tag should be something like `Latest release of the v1 line`
