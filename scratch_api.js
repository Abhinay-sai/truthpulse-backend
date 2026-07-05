const axios = require('axios');

async function test() {
  try {
    const res = await axios.post('https://abhinay-truthpulse-server.onrender.com/auth/register', {
      name: 'Agent Test',
      email: 'abhinaysai123+agenttest1@gmail.com',
      password: 'Password123!'
    });
    console.log("Status:", res.status);
    console.log("Data:", res.data);
  } catch (err) {
    if (err.response) {
      console.log("Status:", err.response.status);
      console.log("Data:", err.response.data);
    } else {
      console.log("Error:", err.message);
    }
  }
}

test();
