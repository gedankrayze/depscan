// Optional oracle check; Rust tests consume npm11-vectors.json directly and do
// not require Node. Pass npm 11's bundled minimatch directory when it is not
// resolvable as the local `minimatch` package.
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const moduleName = process.argv[2] ?? 'minimatch'
const loaded = require(moduleName)
const minimatch = loaded.minimatch ?? loaded
const vectors = JSON.parse(
  readFileSync(new URL('./npm11-vectors.json', import.meta.url), 'utf8'),
)
if (vectors.oracle.unicode !== process.versions.unicode) {
  throw new Error(
    `Unicode runtime mismatch: expected ${vectors.oracle.unicode}, got ${process.versions.unicode}`,
  )
}

let comparisons = 0
for (const entry of vectors.cases) {
  const expected = new Set(entry.matches)
  for (const candidate of vectors.candidates) {
    comparisons += 1
    const actual = minimatch(candidate, entry.pattern)
    if (actual !== expected.has(candidate)) {
      throw new Error(
        `oracle mismatch for ${JSON.stringify(entry.pattern)} against ${JSON.stringify(candidate)}`,
      )
    }
  }
}

for (const pair of vectors.pairs) {
  comparisons += 1
  const actual = minimatch(pair.candidate, pair.pattern)
  if (actual !== pair.matches) {
    throw new Error(
      `oracle mismatch for ${JSON.stringify(pair.pattern)} against ${JSON.stringify(pair.candidate)}`,
    )
  }
}

let rejectionClassifications = 0
for (const rejection of vectors.rejects) {
  rejectionClassifications += 1
  let threw = false
  try {
    minimatch(rejection.candidate ?? 'packages/a', rejection.pattern)
  } catch {
    threw = true
  }
  if (threw !== rejection.npmThrows) {
    throw new Error(
      `oracle rejection classification mismatch for ${JSON.stringify(rejection.pattern)}`,
    )
  }
}

console.log(
  `verified ${comparisons} npm minimatch comparisons and ${rejectionClassifications} rejection classifications with ${moduleName}`,
)
