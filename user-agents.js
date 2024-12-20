const updatedAt = new Date('2024-12-20 00:00:00');
const maxAcceptableAge = 1000 * 60 * 60 * 24 * 120; // 120 days
export { updatedAt };
// Make sure to update all locations.
// Chrome @ Windows NT 10 has just 1 version location: Chrome/104
// Firefox has 2: rv:103.0, Firefox/103.0
// iOS has 2: iPhone OS 15_6, Version/15.6
const agents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0',
];
export function randomList(ignoreAge = false) {
  const diff = +new Date() - +updatedAt;
  if (!ignoreAge && diff > maxAcceptableAge)
    throw new Error('The user agent list is too old; update the package');
  return agents
    .slice()
    .map((value) => ({ value, sorter: Math.random() }))
    .sort((a, b) => a.sorter - b.sorter)
    .map(({ value }) => value);
}
export function random() {
  return randomList()[0];
}