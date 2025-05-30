async function request({ uri, headers }) {
  try {
    const response = await fetch(uri, {
      method: "GET",
      headers,
    });

    return response.json();
  } catch (err) {
    console.log(err);
    throw new Error("Failed to fetch data");
  }
}

module.exports.default = request;
