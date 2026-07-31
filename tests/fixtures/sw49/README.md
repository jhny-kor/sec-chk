# SW49 source-analysis review fixtures

`manifest.json` indexes all 49 official controls. Each pair is executable
source/configuration: the positive side contains the narrow weakness pattern
and the negative side contains its documented guard. The accuracy test runs the
scanner against both sides and refuses an unmeasured PASS. Controls without a
local rule remain explicit `NEEDS_REVIEW`/`NOT_RUN` coverage.

`c01_cross_file/` is the project-context regression pair: the vulnerable
fixture places the nullable source in `Provider.java` and dereference in
`Consumer.java`; the safe pair carries an explicit null guard across files.
