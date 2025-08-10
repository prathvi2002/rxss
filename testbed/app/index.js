const express = require('express');
const app = express();
const port = 6000;

const encodeMap = {
  // comment the special characters you want to filter
  '<': '%3C',
  '>': '%3E',
  '"': '%22',
  "'": '%27',
  '/': '%2F',
  '$': '%24',
  '\\': '%5C',
  '(': '%28',
  ')': '%29',
  '`': '%60',
  ':': '%3A',
  ';': '%3B',
  '{': '%7B',
  '}': '%7D',
  '|': '%7C'
};

function customEncode(str) {
  return str.split('').map(char => encodeMap[char] || char).join('');
}

app.get('/', (req, res) => {
  const input = req.query.input || '';
  const encoded = customEncode(input);
  res.send(`<p>Encoded Output: ${encoded}</p>`);
});

app.listen(port, () => {
  console.log(`App running on http://localhost:${port}`);
});

