# SW49 source-analysis review fixtures

`manifest.json` indexes all 49 official controls. Automated-rule examples are
small source snippets rather than buildable projects. Manual and unsupported
controls use bounded placeholders to verify inventory and report behavior; they
are not ground truth and must not be used to claim measured detection accuracy.

`c01_cross_file/` is the project-context regression pair: the vulnerable
fixture places the nullable source in `Provider.java` and dereference in
`Consumer.java`; the safe pair carries an explicit null guard across files.
