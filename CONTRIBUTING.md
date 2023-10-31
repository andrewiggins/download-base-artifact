# Contributing

## Publishing a new version

1. Run `npm version [patch | minor | major]` to bump the version number in package.json and create new tag
2. Check in package.json version change with commit message (e.g. "Release 1.1.0"): `git commit -m "Release 1.1.0"`
3. Push to GitHub with tags: `git push --tags`
4. Create release in GitHub using new tag with notes on changes
5. Check out new tag (e.g. "v1.1.0"): `git checkout v1.1.0`
6. Move major version to new tag (e.g. "v1"):
   - `git push origin :refs/tags/<major_ver_tagname>; git tag -fa <major_ver_tagname>; git push origin main --tags`
   - Message for major tag should be something like `Latest release of the v1 line`
