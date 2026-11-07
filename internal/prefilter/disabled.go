package prefilter

// disabled makes every expression run. It exists to prove the package changes
// nothing: a build with this set true, swapped in with go build -overlay, is the
// same tree without the filter, and its output must be identical.
const disabled = false
