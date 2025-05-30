const { keys } = require("./keys.js");

global.fetch = jest.fn(() =>
  Promise.resolve({
    json: () => Promise.resolve({ keys }),
  })
);
